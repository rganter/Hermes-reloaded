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
