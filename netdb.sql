CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE hosts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    ip VARCHAR(50),
    hostname VARCHAR(100),
    os VARCHAR(100),
    nbPorts INT,

    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    host_id INT,
    port INT,
    service VARCHAR(100),
    product VARCHAR(100),
    version VARCHAR(100),

    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
