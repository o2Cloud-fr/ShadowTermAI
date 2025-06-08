/**
 * SSH Honeypot avec IA - Un honeypot SSH qui simule un terminal interactif
 * avec des réponses basées sur l'IA pour enregistrer les activités des attaquants.
 * Implémentation Node.js avec support pour simuler wget/curl et enregistrer dans MySQL
 */

const ssh2 = require('ssh2');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const winston = require('winston');
const { format } = require('date-fns');
const sshpk = require('sshpk'); // Utilisation de sshpk pour la génération de clés SSH
const mysql = require('mysql2/promise'); // Module MySQL avec support des promesses
const url = require('url'); // Pour parser les URLs

// Configuration du logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} - ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({ filename: 'honeypot.log' }),
    new winston.transports.Console()
  ]
});

// Configuration du honeypot
const HoneypotConfig = {
  HOST: '0.0.0.0',  // Écoute sur toutes les interfaces
  PORT: 2222,       // Port SSH non standard (le port standard est 22)
  KEY_FILE: 'server.key',
  
  // Utilisateurs et mots de passe faibles pour attirer les attaquants
  USERS: {
    'root': 'password',
    'admin': 'admin123',
    'user': '123456',
    'oracle': 'oracle',
    'test': 'test',
    'guest': 'guest',
    'administrator': 'admin',
    'ftp': 'ftp',
    'postgres': 'postgres',
    'mysql': 'mysql',
    'pi': 'raspberry',
    'support': 'support',
    'backup': 'backup123',
    'web': 'web123',
    'dev': 'dev123',
    'demo': 'demo',
    'user1': 'user1',
    'admin1': 'password1',
    'default': 'default',
    'ubuntu': 'ubuntu',
    'john': '1234',
    'test1': 'test1',
    'monitor': 'monitor',
    'sys': 'sys',
    'netadmin': 'netadmin',
    'vagrant': 'vagrant',
    'security': 'security',
    'service': 'service123',
    'dbadmin': 'dbadmin',
    'hacker': 'toor',
    'anon': 'anon',
    'login': 'login',
    'guest1': 'guest1',
    'root1': 'toor',
    'root2': '1234',

    // Ajouts supplémentaires
    'admin2': 'admin',
    'admin3': 'admin123',
    'test2': 'test2',
    'guest2': 'guest2',
    'temp': 'temp',
    'tempuser': 'temp123',
    'rootadmin': 'admin',
    'git': 'git',
    'jenkins': 'jenkins',
    'docker': 'docker',
    'build': 'build',
    'ci': 'ci123',
    'devops': 'devops',
    'manager': 'manager',
    'superuser': 'superuser',
    'helpdesk': 'helpdesk',
    'local': 'local',
    'admin4': 'admin4',
    'scanner': 'scanner',
    'webuser': 'webuser',
    'db': 'db',
    'sql': 'sql123',
    'readonly': 'readonly',
    'report': 'report',
    'readonlyuser': 'readonly123',
    'remote': 'remote',
    'cloud': 'cloud',
    'sysadmin': 'sysadmin'
  },
  
  // Système simulé
  HOSTNAME: 'prod-server',
  OS_VERSION: 'Ubuntu 20.04.3 LTS',
  KERNEL: '5.11.0-27-generic',
  
  // Configuration MySQL
  DB: {
    host: 'localhost',
    user: 'domain_honeypot_ssh',
    password: 'P@sswords@',
    database: 'domain_honeypot_ssh'
  }
};

// Pool de connexion MySQL
let dbPool;

// Initialisation de la connexion à la base de données
async function initDatabase() {
  try {
    dbPool = await mysql.createPool({
      host: HoneypotConfig.DB.host,
      user: HoneypotConfig.DB.user,
      password: HoneypotConfig.DB.password,
      database: HoneypotConfig.DB.database,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    
    logger.info('Connexion à la base de données établie');
    
    // Vérifier que les tables existent
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS download_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL,
        username VARCHAR(255) NOT NULL,
        url TEXT NOT NULL,
        command TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        session_id VARCHAR(255) NOT NULL,
        risk_score INT DEFAULT 0
      )
    `);
    
    logger.info('Tables de base de données vérifiées');
    return true;
  } catch (error) {
    logger.error(`Erreur lors de l'initialisation de la base de données: ${error.message}`);
    return false;
  }
}

// Fonction pour enregistrer une tentative de téléchargement
async function logDownloadAttempt(ip, username, url, command, sessionId, riskScore) {
  try {
    if (!dbPool) {
      logger.warn('Tentative d\'enregistrement sans connexion à la base de données');
      return false;
    }
    
    const [result] = await dbPool.query(
      'INSERT INTO download_attempts (ip_address, username, url, command, session_id, risk_score) VALUES (?, ?, ?, ?, ?, ?)',
      [ip, username, url, command, sessionId, riskScore]
    );
    
    logger.info(`Tentative de téléchargement enregistrée, ID: ${result.insertId}`);
    return true;
  } catch (error) {
    logger.error(`Erreur lors de l'enregistrement en base de données: ${error.message}`);
    return false;
  }
}

// Chargement de la clé SSH existante
function loadSSHKey() {
  if (!fs.existsSync(HoneypotConfig.KEY_FILE)) {
    logger.error(`La clé SSH n'existe pas dans ${HoneypotConfig.KEY_FILE}. Veuillez créer une clé manuellement.`);
    logger.info(`Conseil: Vous pouvez générer une clé avec la commande: ssh-keygen -t rsa -f ${HoneypotConfig.KEY_FILE} -N ""`);
    throw new Error(`Fichier de clé ${HoneypotConfig.KEY_FILE} non trouvé`);
  }
  
  try {
    // Pour ssh2, les clés doivent être au format Buffer ou String
    const keyData = fs.readFileSync(HoneypotConfig.KEY_FILE, 'utf8');
    return keyData;
  } catch (error) {
    logger.error(`Erreur lors du chargement de la clé SSH: ${error.message}`);
    throw error;
  }
}

// Simulateur de système de fichiers
class FakeFileSystem {
  constructor() {
    this.currentDir = '/home/user';
    this.fileSystem = {
      '/': {
        type: 'dir',
        content: ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var']
      },
      '/home': {
        type: 'dir',
        content: ['user', 'admin']
      },
      '/home/user': {
        type: 'dir',
        content: ['documents', '.bash_history', '.profile', '.bashrc', 'downloads']
      },
      '/home/user/documents': {
        type: 'dir',
        content: ['notes.txt', 'credentials.bak']
      },
      '/home/user/downloads': {
        type: 'dir',
        content: []
      },
      '/home/user/documents/notes.txt': {
        type: 'file',
        content: 'N\'oubliez pas de changer les mots de passe par défaut sur tous les systèmes de production.'
      },
      '/home/user/documents/credentials.bak': {
        type: 'file',
        content: '# Fichier de sauvegarde - À supprimer\ndb_user: admin\ndb_pass: Str0ngP@ssw0rd!\napi_key: a7d8e9f3c2b1e5f8a7c9b2d4'
      },
      '/etc': {
        type: 'dir',
        content: ['passwd', 'shadow', 'hosts', 'resolv.conf', 'ssh']
      },
      '/etc/shadow': {
        type: 'file',
        content: '# Fichier protégé. Permission refusée.'
      }
    };
  }
  
  getCurrentDir() {
    return this.currentDir;
  }
  
  getPathContent(path) {
    path = this._normalizePath(path);
    if (path in this.fileSystem) {
      return this.fileSystem[path];
    }
    return null;
  }
  
  _normalizePath(path) {
    if (!path.startsWith('/')) {
      // Chemin relatif, le combiner avec le répertoire courant
      if (this.currentDir === '/') {
        path = '/' + path;
      } else {
        path = this.currentDir + '/' + path;
      }
    }
    
    // Gestion des '..' et '.'
    const components = path.split('/');
    const normalized = [];
    for (const comp of components) {
      if (comp === '' || comp === '.') {
        continue;
      }
      if (comp === '..' && normalized.length > 0) {
        normalized.pop();
      } else if (comp !== '..') {
        normalized.push(comp);
      }
    }
    
    const result = '/' + normalized.join('/');
    return result !== '' ? result : '/';
  }
  
  changeDirectory(path) {
    path = this._normalizePath(path);
    if (path in this.fileSystem && this.fileSystem[path].type === 'dir') {
      this.currentDir = path;
      return true;
    }
    return false;
  }
  
  // Fonction pour ajouter un fichier simulé au système de fichiers
  addDownloadedFile(filename) {
    const downloadDir = '/home/user/downloads';
    
    // S'assurer que le répertoire de téléchargement existe
    if (!(downloadDir in this.fileSystem)) {
      this.fileSystem[downloadDir] = {
        type: 'dir',
        content: []
      };
    }
    
    // Ajouter le fichier au répertoire de téléchargement s'il n'existe pas déjà
    if (!this.fileSystem[downloadDir].content.includes(filename)) {
      this.fileSystem[downloadDir].content.push(filename);
      
      // Créer une entrée pour le fichier lui-même
      const filePath = `${downloadDir}/${filename}`;
      this.fileSystem[filePath] = {
        type: 'file',
        content: `Contenu simulé du fichier téléchargé: ${filename}`
      };
    }
    
    return `${downloadDir}/${filename}`;
  }
}

// Classe qui simule une réponse intelligente aux commandes SSH
class AICommandSimulator {
  constructor(fs, username, sessionId, ipAddress) {
    this.fileSystem = fs;
    this.username = username;
    this.sessionId = sessionId;
    this.ipAddress = ipAddress;
    
    // Historique des commandes pour analyse comportementale
    this.commandHistory = [];
    // Indicateur de risque, augmente à mesure que l'attaquant exécute des commandes suspectes
    this.riskScore = 0;
  }
  
  async executeCommand(command) {
    // Enregistrer la commande dans l'historique
    this.commandHistory.push({
      command: command,
      timestamp: new Date().toISOString()
    });
    
    // Analyser la commande et renvoyer une réponse appropriée
    command = command.trim();
    const cmdParts = command.split(/\s+/);
    
    if (cmdParts.length === 0) {
      return "";
    }
    
    const mainCmd = cmdParts[0];
    
    // Évaluer le risque de la commande
    this._evaluateRisk(command);
    
    // Simuler un léger délai pour paraître réaliste
    // Note: En Node.js, nous n'allons pas bloquer le thread principal
    // mais nous ferons une petite pause avant d'envoyer la réponse
    
    // Correspondance de commandes
    switch(mainCmd) {
      case 'ls':
      case 'dir':
        return this._handleLs(cmdParts);
      case 'cd':
        return this._handleCd(cmdParts);
      case 'cat':
      case 'less':
      case 'more':
        return this._handleCat(cmdParts);
      case 'pwd':
        return this.fileSystem.getCurrentDir();
      case 'whoami':
        return this.username;
      case 'hostname':
        return HoneypotConfig.HOSTNAME;
      case 'uname':
        if (cmdParts.includes('-a')) {
          return `Linux ${HoneypotConfig.HOSTNAME} ${HoneypotConfig.KERNEL} #1 SMP ${HoneypotConfig.OS_VERSION} x86_64 GNU/Linux`;
        }
        return "Linux";
      case 'ps':
        return this._handlePs();
      case 'id':
        return `uid=1000(${this.username}) gid=1000(${this.username}) groupes=1000(${this.username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)`;
      case 'wget':
        return await this._handleWget(cmdParts, command);
      case 'curl':
        return await this._handleCurl(cmdParts, command);
      case 'chmod':
      case 'chown':
        return `${mainCmd}: opération impossible: Permission refusée`;
      case 'sudo':
        this.riskScore += 10;
        return `${this.username} n'est pas dans le fichier sudoers. Cet incident sera signalé.`;
      case 'exit':
      case 'logout':
        return "exit";
      case 'help':
        return "GNU bash, version 5.0.17(1)-release\nCes commandes shell sont définies de manière interne. Tapez 'help' pour en afficher une liste.";
      default:
        // Commande non reconnue
        if (Math.random() < 0.2) { // 20% de chance de simuler une erreur
          return `${mainCmd}: commande introuvable`;
        }
        return ""; // Pas de sortie, comme dans un vrai terminal pour beaucoup de commandes
    }
  }
  
  _handleLs(cmdParts) {
    let path = this.fileSystem.getCurrentDir();
    const showHidden = cmdParts.includes('-a');
    
    if (cmdParts.length > 1 && !['-l', '-a', '-la', '-al'].includes(cmdParts[cmdParts.length - 1])) {
      path = this.fileSystem._normalizePath(cmdParts[cmdParts.length - 1]);
    }
    
    const content = this.fileSystem.getPathContent(path);
    if (content && content.type === 'dir') {
      let files = content.content;
      if (!showHidden) {
        files = files.filter(f => !f.startsWith('.'));
      }
      return files.join('  ');
    }
    return "ls: impossible d'accéder à '" + path + "': Aucun fichier ou dossier de ce type";
  }
  
  _handleCd(cmdParts) {
    if (cmdParts.length === 1) {
      this.fileSystem.changeDirectory('/home/user');
      return "";
    }
    
    const path = cmdParts[1];
    if (this.fileSystem.changeDirectory(path)) {
      return "";
    } else {
      return `cd: ${path}: Aucun fichier ou dossier de ce type`;
    }
  }
  
  _handleCat(cmdParts) {
    if (cmdParts.length < 2) {
      return "Usage: cat [FICHIER]...";
    }
    
    const path = this.fileSystem._normalizePath(cmdParts[1]);
    const content = this.fileSystem.getPathContent(path);
    
    if (content && content.type === 'file') {
      if (path.includes('shadow')) {
        this.riskScore += 25;
      }
      return content.content;
    } else if (content && content.type === 'dir') {
      return `cat: ${cmdParts[1]}: Est un dossier`;
    } else {
      return `cat: ${cmdParts[1]}: Aucun fichier ou dossier de ce type`;
    }
  }
  
  _handlePs() {
    const processes = `  PID TTY          TIME CMD
    1 ?        00:00:11 systemd
  746 ?        00:00:01 sshd
  823 ?        00:00:03 nginx
  901 ?        00:00:05 mysqld
 1121 ?        00:00:00 cron
 1450 pts/0    00:00:00 bash
 1593 pts/0    00:00:00 ps`;
    return processes;
  }
  
  // Gestion améliorée de wget pour simuler un téléchargement réussi
  async _handleWget(cmdParts, fullCommand) {
    this.riskScore += 15;
    
    // Extraire l'URL du téléchargement
    let targetUrl = null;
    let outputFile = null;
    
    // Analyse des arguments wget
    for (let i = 1; i < cmdParts.length; i++) {
      if (cmdParts[i] === '-O' && i + 1 < cmdParts.length) {
        outputFile = cmdParts[i + 1];
        i++; // Sauter le prochain argument car c'est le nom du fichier
      } else if (!cmdParts[i].startsWith('-')) {
        targetUrl = cmdParts[i];
      }
    }
    
    if (!targetUrl) {
      return "wget: URL manquante";
    }
    
    // Extraire le nom du fichier à partir de l'URL si -O n'est pas spécifié
    if (!outputFile) {
      try {
        const parsedUrl = new URL(targetUrl);
        const pathname = parsedUrl.pathname;
        outputFile = pathname.split('/').pop() || 'index.html';
      } catch (error) {
        outputFile = 'download.dat';
      }
    }
    
    // Simuler un téléchargement réussi
    const simulatedOutput = `
--2025-05-21 ${format(new Date(), 'HH:mm:ss')} --  ${targetUrl}
Résolution de ${targetUrl.split('/')[2]}... 93.184.216.34
Connexion à ${targetUrl.split('/')[2]}|93.184.216.34|:${targetUrl.startsWith('https:') ? '443' : '80'}... connecté.
requête HTTP envoyée, en attente de la réponse... 200 OK
Longueur: ${Math.floor(Math.random() * 1000000) + 1000} (${Math.floor(Math.random() * 1000) + 10}K) [application/octet-stream]
Sauvegarde en : '${outputFile}'

${outputFile}                         100%[=======================================================>]   ${Math.floor(Math.random() * 900) + 100}K  ${Math.floor(Math.random() * 900) + 100}KB/s    ds ${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 10)}s

${format(new Date(), 'yyyy-MM-dd HH:mm:ss')} (${Math.floor(Math.random() * 900) + 100} KB/s) - '${outputFile}' sauvegardé [${Math.floor(Math.random() * 1000000) + 1000}/${Math.floor(Math.random() * 1000000) + 1000}]
`;

    // Ajouter le fichier au système de fichiers simulé
    this.fileSystem.addDownloadedFile(outputFile);
    
    // Enregistrer la tentative de téléchargement dans la base de données
    try {
      await logDownloadAttempt(
        this.ipAddress,
        this.username,
        targetUrl,
        fullCommand,
        this.sessionId,
        this.riskScore
      );
    } catch (error) {
      logger.error(`Erreur lors de l'enregistrement du téléchargement: ${error.message}`);
    }
    
    return simulatedOutput;
  }
  
  // Gestion de curl pour simuler un téléchargement réussi
  async _handleCurl(cmdParts, fullCommand) {
    this.riskScore += 15;
    
    // Extraire l'URL et les options
    let targetUrl = null;
    let outputFile = null;
    let showProgress = true;
    
    // Analyser les options de curl
    for (let i = 1; i < cmdParts.length; i++) {
      if ((cmdParts[i] === '-o' || cmdParts[i] === '--output') && i + 1 < cmdParts.length) {
        outputFile = cmdParts[i + 1];
        i++; // Sauter le prochain argument
      } else if (cmdParts[i] === '-s' || cmdParts[i] === '--silent') {
        showProgress = false;
      } else if (!cmdParts[i].startsWith('-')) {
        targetUrl = cmdParts[i];
      }
    }
    
    if (!targetUrl) {
      return "curl: aucune URL spécifiée!";
    }
    
    // Déterminer le nom du fichier de sortie
    if (!outputFile) {
      try {
        const parsedUrl = new URL(targetUrl);
        const pathname = parsedUrl.pathname;
        outputFile = pathname.split('/').pop() || 'index.html';
      } catch (error) {
        outputFile = 'curl_output.dat';
      }
    }
    
    // Ajouter le fichier téléchargé au système de fichiers simulé
    this.fileSystem.addDownloadedFile(outputFile);
    
    // Enregistrer dans la base de données
    try {
      await logDownloadAttempt(
        this.ipAddress,
        this.username,
        targetUrl,
        fullCommand,
        this.sessionId, 
        this.riskScore
      );
    } catch (error) {
      logger.error(`Erreur lors de l'enregistrement du téléchargement curl: ${error.message}`);
    }
    
    // Simuler une sortie curl selon les options
    if (showProgress) {
      const fileSize = Math.floor(Math.random() * 1000000) + 1000;
      return `  % Total    % Reçus % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 ${fileSize}  100 ${fileSize}    0     0  ${Math.floor(Math.random() * 100000) + 10000}      0  0:00:${Math.floor(Math.random() * 10)}  0:00:${Math.floor(Math.random() * 5)}  0:00:${Math.floor(Math.random() * 5)} ${Math.floor(Math.random() * 100000) + 10000}`;
    } else {
      // Mode silencieux, pas de sortie
      return "";
    }
  }
  
  _evaluateRisk(command) {
    // Analyser la commande pour des activités suspectes
    const suspiciousCmds = ['wget', 'curl', 'nc', 'netcat', 'nmap', 'python', 'perl', 'gcc', 'chmod +x'];
    const dangerousPatterns = ['shadow', 'passwd', '| sh', '| bash', '; sh', '; bash', 'wget', 'curl'];
    
    const cmdLower = command.toLowerCase();
    
    for (const cmd of suspiciousCmds) {
      if (cmdLower.includes(cmd)) {
        this.riskScore += 5;
      }
    }
    
    for (const pattern of dangerousPatterns) {
      if (cmdLower.includes(pattern)) {
        this.riskScore += 10;
      }
    }
    
    // Vérifier les backdoors ou reverse shells
    if (cmdLower.includes('>') || cmdLower.includes('>>')) {
      this.riskScore += 15;
    }
    
    const suspiciousPorts = ['4444', '5555', '9001', '443'];
    for (const port of suspiciousPorts) {
      if (cmdLower.includes(port)) {
        this.riskScore += 20;
        break;
      }
    }
    
    logger.info(`Commande: '${command}' - Score de risque actuel: ${this.riskScore}`);
    
    // Enregistrer plus intensément si le score de risque est élevé
    if (this.riskScore > 50) {
      logger.warn(`ACTIVITÉ SUSPECTE DÉTECTÉE! Commande: '${command}' - Score: ${this.riskScore}`);
      // Ici vous pourriez déclencher des alertes ou des notifications
    }
  }
  
  getAnalysis() {
    return {
      commands: this.commandHistory,
      riskScore: this.riskScore,
      assessment: this._generateAssessment()
    };
  }
  
  _generateAssessment() {
    if (this.riskScore < 20) {
      return "Faible risque - Probablement une exploration basique ou un scan automatisé.";
    } else if (this.riskScore < 50) {
      return "Risque modéré - Tentatives d'accès aux fichiers sensibles ou de reconnaissance.";
    } else if (this.riskScore < 100) {
      return "Risque élevé - Tentatives actives d'exploitation ou de téléchargement de malwares.";
    } else {
      return "Risque critique - Activité malveillante avancée détectée, tentative d'obtention d'accès persistant.";
    }
  }
}

// Classe principale du Honeypot SSH
class SSHHoneypot {
  constructor(host = HoneypotConfig.HOST, port = HoneypotConfig.PORT) {
    this.host = host;
    this.port = port;
    this.serverKey = loadSSHKey(); // Utilisation de la fonction modifiée
    this.running = true;
    
    // Créer le répertoire pour les logs détaillés si nécessaire
    if (!fs.existsSync("sessions")) {
      fs.mkdirSync("sessions");
    }
  }
  
  async start() {
    // Initialiser la base de données avant de démarrer le serveur
    const dbReady = await initDatabase();
    if (!dbReady) {
      logger.warn("Impossible de se connecter à la base de données. Les tentatives de téléchargement ne seront pas enregistrées.");
    }
    
    const server = new ssh2.Server({
      hostKeys: [this.serverKey],
      algorithms: {
        serverHostKey: ['ssh-rsa', 'ssh-dss'],
        cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm', 'aes256-gcm'],
        hmac: ['hmac-sha1', 'hmac-sha2-256', 'hmac-sha2-512'],
        compress: ['none', 'zlib@openssh.com']
      }
    }, (client) => {
      logger.info(`Connexion entrante depuis ${client._sock.remoteAddress}`);
      
      // Créer un ID de session unique
      const sessionId = `session_${client._sock.remoteAddress}_${Date.now()}`;
      
      // Variables de session
      const sessionState = {
        username: "",
        authenticated: false,
        aiSimulator: null, // Sera initialisé après l'authentification
        sessionLog: [],
        authAttempts: 0,
        address: client._sock.remoteAddress,
        sessionId: sessionId
      };
      
      client.on('authentication', (ctx) => {
        sessionState.username = ctx.username;
        sessionState.authAttempts++;
        
        // Enregistrer la tentative d'authentification
        logger.info(`Tentative d'authentification: ${ctx.username}:${ctx.password || '[auth non mot de passe]'} depuis ${sessionState.address} (méthode: ${ctx.method})`);
        
        // Accepter diverses méthodes d'authentification pour être plus permissif avec les honeypots
        if (ctx.method === 'password' && HoneypotConfig.USERS[ctx.username] === ctx.password) {
          logger.warn(`Connexion réussie pour ${ctx.username} depuis ${sessionState.address}`);
          sessionState.authenticated = true;
          sessionState.aiSimulator = new AICommandSimulator(
            new FakeFileSystem(), 
            ctx.username, 
            sessionId,
            sessionState.address
          );
          return ctx.accept();
        } else if (ctx.method === 'none') {
          // Optionnel: permettre auth 'none' après plusieurs tentatives pour observer le comportement
          if (sessionState.authAttempts >= 3) {
            logger.warn(`Autorisant l'accès sans auth pour ${ctx.username} depuis ${sessionState.address}`);
            sessionState.authenticated = true;
            sessionState.aiSimulator = new AICommandSimulator(
              new FakeFileSystem(), 
              ctx.username, 
              sessionId,
              sessionState.address
            );
            return ctx.accept();
          }
          return ctx.reject(['password']);
        } else if (ctx.method === 'publickey') {
          // Simuler l'acceptation d'une clé publique après plusieurs tentatives
          if (sessionState.authAttempts >= 5) {
            logger.warn(`Simulant l'acceptation de clé publique pour ${ctx.username} depuis ${sessionState.address}`);
            sessionState.authenticated = true;
            sessionState.aiSimulator = new AICommandSimulator(
              new FakeFileSystem(), 
              ctx.username, 
              sessionId,
              sessionState.address
            );
            return ctx.accept();
          }
          return ctx.reject(['password']);
        } else {
          // Si la méthode n'est pas reconnue, suggérer 'password'
          return ctx.reject(['password']);
        }
      });
      
      client.on('ready', () => {
        logger.info(`Client authentifié: ${sessionState.username} depuis ${sessionState.address}`);
        
        client.on('session', (accept, reject) => {
          const session = accept();
          
          session.on('exec', async (accept, reject, info) => {
            const stream = accept();
            logger.info(`Commande exécutée directement: ${info.command} par ${sessionState.username} depuis ${sessionState.address}`);
            
            const response = await sessionState.aiSimulator.executeCommand(info.command);
            if (response) {
              stream.write(response + "\r\n");
            }
            
            stream.exit(0);
            stream.end();
          });
          
          session.on('pty', (accept, reject, info) => {
            accept();
          });
          
          session.on('shell', (accept, reject) => {
            const stream = accept();
            
            // Simuler un message de bienvenue
            const now = new Date();
            const banner = `\r
Welcome to ${HoneypotConfig.HOSTNAME} running ${HoneypotConfig.OS_VERSION}
Last login: ${format(now, 'EEE MMM dd HH:mm:ss yyyy')} from 192.168.1.5
\r\n`;
            
            stream.write(banner);
            
            // Simuler un prompt de terminal
            let prompt = `${sessionState.username}@${HoneypotConfig.HOSTNAME}:${sessionState.aiSimulator.fileSystem.getCurrentDir()}$ `;
            stream.write(prompt);
            
            // Variables pour gérer les commandes
            let commandBuffer = "";
            
            stream.on('data', async (data) => {
              // Convertir et traiter les données
              const dataStr = data.toString('utf8');
              
              // Gérer les touches de contrôle et les séquences d'échappement
              for (let i = 0; i < dataStr.length; i++) {
                const c = dataStr[i];
                
                if (c === '\r') { // Enter key
                  stream.write('\r\n');
                  
                  // Exécuter la commande
                  const command = commandBuffer.trim();
                  if (command) {
                    logger.info(`Commande exécutée: '${command}' par ${sessionState.username} depuis ${sessionState.address}`);
                    sessionState.sessionLog.push({
                      timestamp: new Date().toISOString(),
                      command: command
                    });
                    
                    const response = await sessionState.aiSimulator.executeCommand(command);
                    if (response === "exit") {
                      stream.end();
                      return;
                    }
                    
                    if (response) {
                      stream.write(response + '\r\n');
                    }
                  }
                  
                  // Nouveau prompt
                  prompt = `${sessionState.username}@${HoneypotConfig.HOSTNAME}:${sessionState.aiSimulator.fileSystem.getCurrentDir()}$ `;
                  stream.write(prompt);
                  commandBuffer = "";
                } else if (c === '\x7f' || c === '\x08') { // Backspace
                  if (commandBuffer) {
                    commandBuffer = commandBuffer.slice(0, -1);
                    stream.write('\b \b');  // Effacer le caractère
                  }
                } else if (c === '\x03') { // Ctrl+C
                  stream.write('^C\r\n');
                  commandBuffer = "";
                  prompt = `${sessionState.username}@${HoneypotConfig.HOSTNAME}:${sessionState.aiSimulator.fileSystem.getCurrentDir()}$ `;
                  stream.write(prompt);
                } else if (c === '\t') { // Tab (complétion)
                  // Une implémentation simple de la complétion pourrait être ajoutée ici
                } else if (c >= ' ' && c <= '~') { // Caractères imprimables
                  commandBuffer += c;
                  stream.write(c);
                }
              }
            });
            
            stream.on('close', () => {
              // Enregistrer l'analyse de la session
              this._saveSessionData(sessionState);
            });
          });
        });
      });
      
      client.on('error', (err) => {
        logger.error(`Erreur SSH: ${err.message}`);
      });
      
      client.on('end', () => {
        if (sessionState.sessionLog.length > 0) {
          // Enregistrer l'analyse de la session si elle n'a pas été enregistrée
          this._saveSessionData(sessionState);
        }
      });
    }).listen(this.port, this.host, () => {
      logger.info(`Honeypot SSH démarré sur ${this.host}:${this.port}`);
    });
    
    server.on('error', (err) => {
      logger.error(`Erreur du serveur SSH: ${err.message}`);
    });
  }
  
  async _saveSessionData(sessionState) {
    // Créer un fichier unique pour la session
    const sessionFile = `sessions/session_${sessionState.sessionId}.json`;
    
    const analysis = sessionState.aiSimulator.getAnalysis();
    
    const sessionData = {
      session_id: sessionState.sessionId,
      ip_address: sessionState.address,
      username: sessionState.username,
      start_time: sessionState.sessionLog.length > 0 ? sessionState.sessionLog[0].timestamp : new Date().toISOString(),
      end_time: new Date().toISOString(),
      authenticated: sessionState.authenticated,
      auth_attempts: sessionState.authAttempts,
      commands: sessionState.sessionLog,
      risk_score: analysis.riskScore,
      assessment: analysis.assessment
    };
    
    fs.writeFileSync(sessionFile, JSON.stringify(sessionData, null, 2));
    
    logger.info(`Session ${sessionState.sessionId} enregistrée. Score de risque: ${analysis.riskScore}`);
    
    // Si le score de risque est élevé, on pourrait envoyer une alerte
    if (analysis.riskScore > 75) {
      logger.error(`ALERTE: Session à haut risque détectée! IP: ${sessionState.address}, Score: ${analysis.riskScore}`);
      // Envoi d'alerte par email, webhook, etc.
    }
    
    // Tentative d'enregistrement dans la base de données
    try {
      if (dbPool) {
        await dbPool.query(
          'INSERT INTO sessions (session_id, ip_address, username, start_time, end_time, auth_attempts, risk_score, assessment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [
            sessionState.sessionId,
            sessionState.address,
            sessionState.username,
            sessionState.sessionLog.length > 0 ? sessionState.sessionLog[0].timestamp : new Date().toISOString(),
            new Date().toISOString(),
            sessionState.authAttempts,
            analysis.riskScore,
            analysis.assessment
          ]
        );
        
        // Enregistrer les commandes individuelles
        for (const cmd of sessionState.sessionLog) {
          await dbPool.query(
            'INSERT INTO commands (session_id, command, timestamp) VALUES (?, ?, ?)',
            [sessionState.sessionId, cmd.command, cmd.timestamp]
          );
        }
        
        logger.info(`Session ${sessionState.sessionId} enregistrée dans la base de données.`);
      }
    } catch (error) {
      logger.error(`Erreur lors de l'enregistrement de la session dans la base de données: ${error.message}`);
    }
  }
}

// Point d'entrée principal
async function main() {
  try {
    // Vérifier les dépendances
    logger.info("Vérification des dépendances...");
    try {
      require('ssh2');
      require('winston');
      require('sshpk');
      require('mysql2/promise');
    } catch (err) {
      logger.error(`Dépendances manquantes. Veuillez installer les modules nécessaires avec npm:`);
      logger.error("npm install ssh2 winston date-fns sshpk mysql2");
      process.exit(1);
    }
    
    // Démarrer le honeypot
    const honeypot = new SSHHoneypot();
    await honeypot.start();
    
  } catch (err) {
    logger.error(`Erreur fatale: ${err.message}`);
    process.exit(1);
  }
}

// Démarrer l'application
main();