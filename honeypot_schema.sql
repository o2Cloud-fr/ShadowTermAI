-- Schéma SQL pour le Honeypot SSH avec IA
-- Compatible avec MariaDB 10.6
-- Encodage: UTF-8

-- Suppression des tables si elles existent déjà
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS download_attempts;
DROP TABLE IF EXISTS sessions;

-- Table des sessions: stocke les informations sur chaque session SSH
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(255) NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME NOT NULL,
    auth_attempts INT DEFAULT 0,
    risk_score INT DEFAULT 0,
    assessment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_ip_address (ip_address),
    INDEX idx_username (username),
    INDEX idx_risk_score (risk_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table des commandes: stocke chaque commande exécutée dans une session
CREATE TABLE commands (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table des tentatives de téléchargement: stocke les détails des fichiers téléchargés
CREATE TABLE download_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    command TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    session_id VARCHAR(255) NOT NULL,
    risk_score INT DEFAULT 0,
    file_hash VARCHAR(64) DEFAULT NULL,
    file_size INT DEFAULT NULL,
    file_type VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Suppression de la contrainte FOREIGN KEY pour permettre l'enregistrement
    -- même si la session n'a pas encore été sauvegardée
    INDEX idx_ip_address (ip_address),
    INDEX idx_session_id (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table des statistiques: agrège les données pour tableaux de bord et rapports
CREATE TABLE statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    total_sessions INT DEFAULT 0,
    total_commands INT DEFAULT 0,
    total_downloads INT DEFAULT 0,
    avg_risk_score DECIMAL(5,2) DEFAULT 0.00,
    high_risk_sessions INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_date (date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table des alertes: stocke les événements à haut risque pour notification
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    alert_type ENUM('HIGH_RISK', 'SUSPICIOUS_DOWNLOAD', 'REPEATED_ACCESS', 'POTENTIAL_EXPLOIT') NOT NULL,
    details TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_handled BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    INDEX idx_is_handled (is_handled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table de configuration: stocke les paramètres configurables du honeypot
CREATE TABLE config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    param_name VARCHAR(100) NOT NULL,
    param_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_param_name (param_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Trigger pour mettre à jour les statistiques après insertion d'une session
DELIMITER //
CREATE TRIGGER after_session_insert
AFTER INSERT ON sessions
FOR EACH ROW
BEGIN
    DECLARE stat_date DATE;
    SET stat_date = DATE(NEW.end_time);
    
    INSERT INTO statistics (date, total_sessions, high_risk_sessions)
    VALUES (stat_date, 1, IF(NEW.risk_score > 75, 1, 0))
    ON DUPLICATE KEY UPDATE 
        total_sessions = total_sessions + 1,
        high_risk_sessions = high_risk_sessions + IF(NEW.risk_score > 75, 1, 0),
        avg_risk_score = (avg_risk_score * (total_sessions - 1) + NEW.risk_score) / total_sessions;
        
    -- Créer une alerte pour les sessions à haut risque
    IF NEW.risk_score > 75 THEN
        INSERT INTO alerts (session_id, ip_address, alert_type, details)
        VALUES (NEW.session_id, NEW.ip_address, 'HIGH_RISK', 
                CONCAT('Session à haut risque détectée. Score: ', NEW.risk_score, '. Évaluation: ', NEW.assessment));
    END IF;
END //
DELIMITER ;

-- Trigger pour mettre à jour les statistiques après insertion d'une commande
DELIMITER //
CREATE TRIGGER after_command_insert
AFTER INSERT ON commands
FOR EACH ROW
BEGIN
    DECLARE stat_date DATE;
    SET stat_date = DATE(NEW.timestamp);
    
    INSERT INTO statistics (date, total_commands)
    VALUES (stat_date, 1)
    ON DUPLICATE KEY UPDATE 
        total_commands = total_commands + 1;
END //
DELIMITER ;

-- Trigger pour mettre à jour les statistiques après insertion d'un téléchargement
DELIMITER //
CREATE TRIGGER after_download_insert
AFTER INSERT ON download_attempts
FOR EACH ROW
BEGIN
    DECLARE stat_date DATE;
    SET stat_date = DATE(NEW.timestamp);
    
    INSERT INTO statistics (date, total_downloads)
    VALUES (stat_date, 1)
    ON DUPLICATE KEY UPDATE 
        total_downloads = total_downloads + 1;
        
    -- Créer une alerte pour les téléchargements suspects
    IF NEW.risk_score > 50 THEN
        INSERT INTO alerts (session_id, ip_address, alert_type, details)
        VALUES (NEW.session_id, NEW.ip_address, 'SUSPICIOUS_DOWNLOAD', 
                CONCAT('Téléchargement suspect détecté. URL: ', NEW.url, '. Score: ', NEW.risk_score));
    END IF;
END //
DELIMITER ;

-- Insertion des valeurs de configuration par défaut
INSERT INTO config (param_name, param_value, description) VALUES
('alert_risk_threshold', '75', 'Seuil de score de risque pour générer une alerte automatique'),
('max_auth_attempts', '5', 'Nombre maximal de tentatives d''authentification avant simulation d''acceptation'),
('log_level', 'info', 'Niveau de journalisation (debug, info, warn, error)'),
('email_alerts', 'false', 'Activer/désactiver les alertes par email'),
('alert_email', 'admin@example.com', 'Adresse email pour recevoir les alertes'),
('auto_ban_threshold', '100', 'Score de risque pour bannissement automatique d''IP (0 = désactivé)'),
('simulate_vulnerabilities', 'true', 'Simuler des vulnérabilités et des fichiers sensibles'),
('download_dir', '/home/user/downloads', 'Répertoire pour les téléchargements simulés');

-- Vues pour faciliter la génération de rapports

-- Vue des sessions à haut risque
CREATE VIEW high_risk_sessions AS
SELECT s.*, 
       COUNT(c.id) AS command_count, 
       COUNT(d.id) AS download_count
FROM sessions s
LEFT JOIN commands c ON s.session_id = c.session_id
LEFT JOIN download_attempts d ON s.session_id = d.session_id
WHERE s.risk_score > 75
GROUP BY s.id
ORDER BY s.risk_score DESC;

-- Vue des statistiques par adresse IP
CREATE VIEW ip_statistics AS
SELECT 
    ip_address,
    COUNT(DISTINCT session_id) AS session_count,
    AVG(risk_score) AS avg_risk_score,
    MAX(risk_score) AS max_risk_score,
    COUNT(DISTINCT DATE(start_time)) AS unique_days_active,
    MAX(end_time) AS last_seen
FROM sessions
GROUP BY ip_address
ORDER BY avg_risk_score DESC;

-- Vue des tentatives de téléchargement groupées par URL
CREATE VIEW download_urls AS
SELECT 
    url,
    COUNT(*) AS attempt_count,
    COUNT(DISTINCT ip_address) AS unique_ips,
    COUNT(DISTINCT session_id) AS unique_sessions,
    AVG(risk_score) AS avg_risk_score,
    MAX(timestamp) AS last_attempt
FROM download_attempts
GROUP BY url
ORDER BY attempt_count DESC;

-- Procédure stockée pour nettoyer les anciennes données
DELIMITER //
CREATE PROCEDURE cleanup_old_data(IN days_to_keep INT)
BEGIN
    DECLARE cutoff_date DATE;
    SET cutoff_date = DATE_SUB(CURRENT_DATE(), INTERVAL days_to_keep DAY);
    
    -- Suppression des anciennes sessions et données associées (les triggers supprimeront en cascade)
    DELETE FROM sessions WHERE DATE(end_time) < cutoff_date;
    
    -- Nettoyage des statistiques (optionnel, peut être conservé pour historique)
    -- DELETE FROM statistics WHERE date < cutoff_date;
END //
DELIMITER ;

-- Accorder les privilèges nécessaires à l'utilisateur de l'application
-- GRANT SELECT, INSERT, UPDATE, DELETE ON vofa2334_domain_honeypot_ssh.* TO 'vofa2334_domain_honeypot_ssh'@'localhost';
-- FLUSH PRIVILEGES;
