use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_mock_mycat_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // 1. Send MyCAT 1.6 Handshake Packet
        // Server version: 5.6.29-mycat-1.6-RELEASE\0
        // thread_id: 1 (u32)
        // seed: 8 bytes + \0
        // serverCapabilities: CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG |
        //                     CLIENT_CONNECT_WITH_DB | CLIENT_LOCAL_FILES | CLIENT_IGNORE_SPACE |
        //                     CLIENT_PROTOCOL_41 | CLIENT_INTERACTIVE | CLIENT_IGNORE_SIGPIPE |
        //                     CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION (0xF7CF or 0xA20D etc.)
        // serverCharsetIndex: 33 (utf8_general_ci)
        // serverStatus: 2 (AUTOCOMMIT)
        // FILLER_13: 13 zeros
        // restOfScrambleBuff: 12 bytes + \0
        let mut hs_payload = Vec::new();
        hs_payload.push(10); // protocol version
        hs_payload.extend_from_slice(b"5.6.29-mycat-1.6-RELEASE\0");
        hs_payload.extend_from_slice(&1u32.to_le_bytes()); // thread id
        hs_payload.extend_from_slice(b"12345678\0"); // seed1
        hs_payload.extend_from_slice(&0xA20Du16.to_le_bytes()); // serverCapabilities (UB2)
        hs_payload.push(33); // serverCharsetIndex
        hs_payload.extend_from_slice(&2u16.to_le_bytes()); // serverStatus
        hs_payload.extend_from_slice(&[0u8; 13]); // FILLER_13
        hs_payload.extend_from_slice(b"87654321abcd\0"); // seed2

        let mut hs_packet = Vec::new();
        let len = hs_payload.len() as u32;
        hs_packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
        hs_packet.push(0); // packet id = 0
        hs_packet.extend_from_slice(&hs_payload);

        socket.write_all(&hs_packet).await.unwrap();
        println!(
            "Server: Sent MyCAT Handshake packet (len = {})",
            hs_packet.len()
        );

        // 2. Read HandshakeResponse from client
        let mut header = [0u8; 4];
        socket.read_exact(&mut header).await.unwrap();
        let payload_len =
            (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
        let seq = header[3];
        println!(
            "Server: Received client HandshakeResponse header: len = {}, seq = {}",
            payload_len, seq
        );

        let mut client_resp = vec![0u8; payload_len];
        socket.read_exact(&mut client_resp).await.unwrap();
        println!("Server: Client response payload: {:02x?}", client_resp);

        // Simulate MyCAT AuthPacket.read(data)
        let mut full_packet = Vec::new();
        full_packet.extend_from_slice(&header);
        full_packet.extend_from_slice(&client_resp);

        // Verify MyCAT 1.6 parsing
        assert!(full_packet.len() >= 36);
        let client_flags = u32::from_le_bytes(full_packet[4..8].try_into().unwrap());
        let max_packet_size = u32::from_le_bytes(full_packet[8..12].try_into().unwrap());
        let charset_index = full_packet[12];
        println!(
            "MyCAT simulated AuthPacket: client_flags={:#x}, max_packet_size={}, charset_index={}",
            client_flags, max_packet_size, charset_index
        );
        assert_eq!(
            charset_index, 33,
            "Client must respect server's default collation 33"
        );
        assert_eq!(
            max_packet_size,
            16 * 1024 * 1024,
            "Client must use 16MB max packet size"
        );

        // 3. Send AUTH_OK
        // byte[] AUTH_OK = new byte[] { 7, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0 };
        let auth_ok = [7u8, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
        socket.write_all(&auth_ok).await.unwrap();
        println!("Server: Sent AUTH_OK");

        // 4. Read next command from client (if any)
        let mut cmd_header = [0u8; 4];
        if let Ok(Ok(_)) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            socket.read_exact(&mut cmd_header),
        )
        .await
        {
            let cmd_len = (cmd_header[0] as usize)
                | ((cmd_header[1] as usize) << 8)
                | ((cmd_header[2] as usize) << 16);
            let cmd_seq = cmd_header[3];
            println!(
                "Server: Next command header: len = {}, seq = {}",
                cmd_len, cmd_seq
            );
            let mut cmd_body = vec![0u8; cmd_len];
            socket.read_exact(&mut cmd_body).await.unwrap();
            println!(
                "Server: Command: {:02x?} (string: {:?})",
                cmd_body,
                String::from_utf8_lossy(&cmd_body)
            );

            // Send OkPacket.OK: byte[] OK = new byte[] { 7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0 };
            let ok = [7u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
            socket.write_all(&ok).await.unwrap();
            println!("Server: Sent OkPacket.OK");
        } else {
            println!(
                "Server: No further commands sent by client (expected when post-connect queries are disabled)."
            );
        }
    });

    // Client side: Connect using sqlx MySqlPoolOptions exactly like rustgrid-mysql driver.rs
    use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};

    let opts = MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(addr.port())
        .username("root")
        .password("123456")
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .timezone(None)
        .set_names(false)
        .statement_cache_capacity(0);

    let pool_options = MySqlPoolOptions::new()
        .max_connections(5)
        .test_before_acquire(false);

    println!("Client: Connecting with MySqlPoolOptions...");
    let res = pool_options.connect_with(opts).await;
    match res {
        Ok(pool) => {
            println!("Client: Pool connected successfully!");
            pool.close().await;
        }
        Err(e) => panic!("Client connect failed: {:?}", e),
    }

    let _ = server_handle.await;
}

fn write_lenenc_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    if bytes.len() < 251 {
        buf.push(bytes.len() as u8);
    } else {
        panic!("len >= 251 not handled in mock");
    }
    buf.extend_from_slice(bytes);
}

fn make_field_packet(name: &str, seq: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    // catalog
    write_lenenc_str(&mut payload, "def");
    // db (empty)
    payload.push(0);
    // table (empty)
    payload.push(0);
    // org_table (empty)
    payload.push(0);
    // name
    write_lenenc_str(&mut payload, name);
    // org_name (empty)
    payload.push(0);
    // next_len = 0x0c
    payload.push(0x0c);
    // collation = 0 (like MyCAT when CharsetUtil doesn't know Cp1252)
    payload.extend_from_slice(&0u16.to_le_bytes());
    // max_size = 0
    payload.extend_from_slice(&0u32.to_le_bytes());
    // type = 0xfd (VAR_STRING)
    payload.push(0xfd);
    // flags = 0
    payload.extend_from_slice(&0u16.to_le_bytes());
    // decimals = 0
    payload.push(0);
    // filler 2 bytes
    payload.extend_from_slice(&[0, 0]);

    let mut packet = Vec::new();
    let len = payload.len() as u32;
    packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&payload);
    packet
}

fn make_err_packet(msg: &str, seq: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0xff); // ERR packet header
    payload.extend_from_slice(&1146u16.to_le_bytes()); // ER_NO_SUCH_TABLE
    payload.push(b'#');
    payload.extend_from_slice(b"42S02");
    payload.extend_from_slice(msg.as_bytes());

    let mut packet = Vec::new();
    let len = payload.len() as u32;
    packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&payload);
    packet
}

fn make_multi_row_packet(cols: &[&str], seq: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    for col in cols {
        write_lenenc_str(&mut payload, col);
    }

    let mut packet = Vec::new();
    let len = payload.len() as u32;
    packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&payload);
    packet
}

fn make_row_packet(col0: &str, col1: &str, seq: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    write_lenenc_str(&mut payload, col0);
    write_lenenc_str(&mut payload, col1);

    let mut packet = Vec::new();
    let len = payload.len() as u32;
    packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&payload);
    packet
}

#[tokio::test]
async fn test_mock_mycat_show_full_tables() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // 1. Send Handshake
        let mut hs_payload = Vec::new();
        hs_payload.push(10);
        hs_payload.extend_from_slice(b"5.6.29-mycat-1.6-RELEASE\0");
        hs_payload.extend_from_slice(&1u32.to_le_bytes());
        hs_payload.extend_from_slice(b"12345678\0");
        hs_payload.extend_from_slice(&0xA20Du16.to_le_bytes());
        hs_payload.push(33);
        hs_payload.extend_from_slice(&2u16.to_le_bytes());
        hs_payload.extend_from_slice(&[0u8; 13]);
        hs_payload.extend_from_slice(b"87654321abcd\0");

        let mut hs_packet = Vec::new();
        let len = hs_payload.len() as u32;
        hs_packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
        hs_packet.push(0);
        hs_packet.extend_from_slice(&hs_payload);
        socket.write_all(&hs_packet).await.unwrap();

        // 2. Read HandshakeResponse
        let mut header = [0u8; 4];
        socket.read_exact(&mut header).await.unwrap();
        let payload_len =
            (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
        let mut client_resp = vec![0u8; payload_len];
        socket.read_exact(&mut client_resp).await.unwrap();

        // 3. Send AUTH_OK
        let auth_ok = [7u8, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
        socket.write_all(&auth_ok).await.unwrap();

        // 4. Handle commands in a loop
        loop {
            let mut cmd_hdr = [0u8; 4];
            if socket.read_exact(&mut cmd_hdr).await.is_err() {
                break;
            }
            let cmd_len = (cmd_hdr[0] as usize)
                | ((cmd_hdr[1] as usize) << 8)
                | ((cmd_hdr[2] as usize) << 16);
            let mut cmd_body = vec![0u8; cmd_len];
            socket.read_exact(&mut cmd_body).await.unwrap();

            let cmd_type = cmd_body[0];
            if cmd_type == 0x01 {
                // COM_QUIT
                break;
            }
            let sql = String::from_utf8_lossy(&cmd_body[1..]).to_string();
            println!("MockServer: Received command {:#x}: {}", cmd_type, sql);

            if sql.starts_with("USE ") {
                // OK packet
                let ok = [7u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
                socket.write_all(&ok).await.unwrap();
            } else if sql == "SHOW FULL TABLES" {
                // MyCAT response:
                // Header (2 columns), seq 1
                let header_pkt = [1u8, 0, 0, 1, 2];
                socket.write_all(&header_pkt).await.unwrap();

                // Field 0: "Tables in YUNC_MAIN_DB", seq 2
                let f0 = make_field_packet("Tables in YUNC_MAIN_DB", 2);
                socket.write_all(&f0).await.unwrap();

                // Field 1: "Table_type  ", seq 3
                let f1 = make_field_packet("Table_type  ", 3);
                socket.write_all(&f1).await.unwrap();

                // EOF, seq 4
                let eof1 = [5u8, 0, 0, 4, 0xfe, 0, 0, 2, 0];
                socket.write_all(&eof1).await.unwrap();

                // Row 1: "tbl_user", "BASE TABLE", seq 5
                let r1 = make_row_packet("tbl_user", "BASE TABLE", 5);
                socket.write_all(&r1).await.unwrap();

                // Row 2: "tbl_order", "BASE TABLE", seq 6
                let r2 = make_row_packet("tbl_order", "BASE TABLE", 6);
                socket.write_all(&r2).await.unwrap();

                // EOF, seq 7
                let eof2 = [5u8, 0, 0, 7, 0xfe, 0, 0, 2, 0];
                socket.write_all(&eof2).await.unwrap();
            } else {
                panic!("Unexpected query: {}", sql);
            }
        }
    });

    use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
    use sqlx::{Column, Row};

    let opts = MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(addr.port())
        .username("root")
        .password("123456")
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .timezone(None)
        .set_names(false)
        .statement_cache_capacity(0);

    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect_with(opts)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql("USE `YUNC_MAIN_DB`")
        .execute(&mut *conn)
        .await
        .unwrap();

    let rows = sqlx::raw_sql("SHOW FULL TABLES")
        .fetch_all(&mut *conn)
        .await
        .unwrap();

    println!("Client: Got {} rows", rows.len());
    for (i, row) in rows.iter().enumerate() {
        for (ci, col) in row.columns().iter().enumerate() {
            println!("Row {} Col {}: name={:?}", i, ci, col.name());
        }
        let col0: String = row.try_get(0).unwrap();
        let col1: String = row.try_get(1).unwrap();
        println!("Row {}: col0={:?}, col1={:?}", i, col0, col1);
    }
    drop(conn);
    pool.close().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_mock_mycat_connection_trait_list_tables_and_columns() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((mut socket, _)) = res else { break };
                    tokio::spawn(async move {
                        let mut hs_payload = Vec::new();
                        hs_payload.push(10);
                        hs_payload.extend_from_slice(b"5.6.29-mycat-1.6-RELEASE\0");
                        hs_payload.extend_from_slice(&1u32.to_le_bytes());
                        hs_payload.extend_from_slice(b"12345678\0");
                        hs_payload.extend_from_slice(&0xA20Du16.to_le_bytes());
                        hs_payload.push(33);
                        hs_payload.extend_from_slice(&2u16.to_le_bytes());
                        hs_payload.extend_from_slice(&[0u8; 13]);
                        hs_payload.extend_from_slice(b"87654321abcd\0");

                        let mut hs_packet = Vec::new();
                        let len = hs_payload.len() as u32;
                        hs_packet.extend_from_slice(&(len & 0xFFFFFF).to_le_bytes()[..3]);
                        hs_packet.push(0);
                        hs_packet.extend_from_slice(&hs_payload);
                        if socket.write_all(&hs_packet).await.is_err() {
                            return;
                        }

                        let mut header = [0u8; 4];
                        if socket.read_exact(&mut header).await.is_err() {
                            return;
                        }
                        let payload_len = (header[0] as usize)
                            | ((header[1] as usize) << 8)
                            | ((header[2] as usize) << 16);
                        let mut client_resp = vec![0u8; payload_len];
                        if socket.read_exact(&mut client_resp).await.is_err() {
                            return;
                        }

                        let auth_ok = [7u8, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
                        if socket.write_all(&auth_ok).await.is_err() {
                            return;
                        }

                        loop {
                            let mut cmd_hdr = [0u8; 4];
                            if socket.read_exact(&mut cmd_hdr).await.is_err() {
                                break;
                            }
                            let cmd_len = (cmd_hdr[0] as usize)
                                | ((cmd_hdr[1] as usize) << 8)
                                | ((cmd_hdr[2] as usize) << 16);
                            let mut cmd_body = vec![0u8; cmd_len];
                            if socket.read_exact(&mut cmd_body).await.is_err() {
                                break;
                            }

                            let cmd_type = cmd_body[0];
                            if cmd_type == 0x01 {
                                break;
                            }
                            let sql = String::from_utf8_lossy(&cmd_body[1..]).to_string();

                            if sql.starts_with("USE ") {
                                let ok = [7u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
                                if socket.write_all(&ok).await.is_err() {
                                    break;
                                }
                            } else if sql.contains("SHOW FULL TABLES") || sql.contains("SHOW TABLES") {
                                let header_pkt = [1u8, 0, 0, 1, 2];
                                if socket.write_all(&header_pkt).await.is_err() {
                                    break;
                                }

                                let f0 = make_field_packet("Tables in mycatdb", 2);
                                if socket.write_all(&f0).await.is_err() {
                                    break;
                                }
                                let f1 = make_field_packet("Table_type  ", 3);
                                if socket.write_all(&f1).await.is_err() {
                                    break;
                                }

                                let eof1 = [5u8, 0, 0, 4, 0xfe, 0, 0, 2, 0];
                                if socket.write_all(&eof1).await.is_err() {
                                    break;
                                }

                                let r1 = make_row_packet("tbl_user", "BASE TABLE", 5);
                                if socket.write_all(&r1).await.is_err() {
                                    break;
                                }
                                let r2 = make_row_packet("tbl_order", "BASE TABLE", 6);
                                if socket.write_all(&r2).await.is_err() {
                                    break;
                                }
                                let r3 = make_row_packet("v_stats", "VIEW", 7);
                                if socket.write_all(&r3).await.is_err() {
                                    break;
                                }

                                let eof2 = [5u8, 0, 0, 8, 0xfe, 0, 0, 2, 0];
                                if socket.write_all(&eof2).await.is_err() {
                                    break;
                                }
                            } else if sql.contains("information_schema.views") {
                                let err = make_err_packet("Table 'information_schema.views' doesn't exist", 1);
                                if socket.write_all(&err).await.is_err() {
                                    break;
                                }
                            } else if sql.contains("information_schema.columns") {
                                let err = make_err_packet("Table 'information_schema.columns' doesn't exist", 1);
                                if socket.write_all(&err).await.is_err() {
                                    break;
                                }
                            } else if sql.contains("SHOW FULL COLUMNS") || sql.contains("SHOW COLUMNS") {
                                let header_pkt = [1u8, 0, 0, 1, 9];
                                if socket.write_all(&header_pkt).await.is_err() {
                                    break;
                                }

                                let col_names = [
                                    "Field", "Type", "Collation", "Null", "Key", "Default", "Extra",
                                    "Privileges", "Comment",
                                ];
                                for (idx, cname) in col_names.iter().enumerate() {
                                    let fp = make_field_packet(cname, (idx + 2) as u8);
                                    if socket.write_all(&fp).await.is_err() {
                                        break;
                                    }
                                }

                                let eof1 = [5u8, 0, 0, 11, 0xfe, 0, 0, 2, 0];
                                if socket.write_all(&eof1).await.is_err() {
                                    break;
                                }

                                let r0 = make_multi_row_packet(
                                    &[
                                        "id",
                                        "bigint(20)",
                                        "",
                                        "NO",
                                        "PRI",
                                        "",
                                        "auto_increment",
                                        "select,insert,update,references",
                                        "",
                                    ],
                                    12,
                                );
                                if socket.write_all(&r0).await.is_err() {
                                    break;
                                }

                                let r1 = make_multi_row_packet(
                                    &[
                                        "nickname",
                                        "varchar(64)",
                                        "utf8_general_ci",
                                        "YES",
                                        "",
                                        "",
                                        "",
                                        "select,insert,update,references",
                                        "user nickname",
                                    ],
                                    13,
                                );
                                if socket.write_all(&r1).await.is_err() {
                                    break;
                                }

                                let eof2 = [5u8, 0, 0, 14, 0xfe, 0, 0, 2, 0];
                                if socket.write_all(&eof2).await.is_err() {
                                    break;
                                }
                            } else {
                                let ok = [7u8, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
                                if socket.write_all(&ok).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    use rustgrid_core::{Connection, ObjectKind};
    use rustgrid_mysql::{Engine, MysqlConnection};
    use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};

    let opts = MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(addr.port())
        .username("root")
        .password("123456")
        .pipes_as_concat(false)
        .no_engine_substitution(false)
        .timezone(None)
        .set_names(false)
        .statement_cache_capacity(0);

    let pool = MySqlPoolOptions::new()
        .max_connections(2)
        .test_before_acquire(false)
        .connect_with(opts)
        .await
        .unwrap();

    let conn = MysqlConnection::new(pool, Engine::MySql, None);

    // Test list_tables
    let tables = conn.list_tables("mycatdb").await.unwrap();
    assert_eq!(tables.len(), 3);
    assert_eq!(tables[0].name, "tbl_order");
    assert_eq!(tables[0].kind, ObjectKind::Table);
    assert_eq!(tables[1].name, "tbl_user");
    assert_eq!(tables[1].kind, ObjectKind::Table);
    assert_eq!(tables[2].name, "v_stats");
    assert_eq!(tables[2].kind, ObjectKind::View);

    // Test columns
    let cols = conn.columns("mycatdb", "tbl_user").await.unwrap();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0].name, "id");
    assert_eq!(cols[0].data_type, "bigint(20)");
    assert_eq!(cols[0].primary_key, true);
    assert_eq!(cols[0].nullable, false);
    assert_eq!(cols[0].comment, "");

    assert_eq!(cols[1].name, "nickname");
    assert_eq!(cols[1].data_type, "varchar(64)");
    assert_eq!(cols[1].primary_key, false);
    assert_eq!(cols[1].nullable, true);
    assert_eq!(cols[1].comment, "user nickname");

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}
