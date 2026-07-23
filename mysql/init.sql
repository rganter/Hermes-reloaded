CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(190) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,   -- SHA512-CRYPT Hash (kompatibel zu Dovecot)
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Einzelne Konfigurationszeile (Singleton, id = 1) fuer den vorgelagerten
-- Smarthost. Wird ueber die WebGUI gepflegt. Benutzer/Passwort sind
-- optional - manche Smarthosts arbeiten mit IP-Whitelisting statt Auth.
CREATE TABLE IF NOT EXISTS settings (
  id INT PRIMARY KEY DEFAULT 1,
  smarthost VARCHAR(255) NOT NULL,
  smarthost_port INT NOT NULL DEFAULT 587,
  smarthost_user VARCHAR(255) NULL,
  smarthost_password VARCHAR(255) NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_settings (
  id INT PRIMARY KEY DEFAULT 1,
  max_login_failures INT NOT NULL DEFAULT 5,
  block_duration_minutes INT NOT NULL DEFAULT 30,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_blocks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  failed_attempts INT NOT NULL DEFAULT 0,
  first_failure_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_failure_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  blocked_until DATETIME NULL
);

CREATE TABLE IF NOT EXISTS log_monitor_state (
  id INT PRIMARY KEY DEFAULT 1,
  log_inode VARCHAR(64) NULL,
  log_offset BIGINT NOT NULL DEFAULT 0
);
