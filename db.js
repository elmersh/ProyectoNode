/**
 * Módulo de conexión a Azure SQL Database
 *
 * Seguridad implementada:
 * - Credenciales desde variables de entorno (NO hardcodeadas)
 * - Conexión cifrada con TLS
 * - Pool de conexiones con límites configurados
 */

const sql = require('mssql');

const config = {
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT) || 1433,
  options: {
    encrypt: true, // Obligatorio para Azure SQL
    trustServerCertificate: false,
    enableArithAbort: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

let pool = null;

async function getPool() {
  // Si el pool existe pero se desconectó, limpiarlo para reconectar
  if (pool && !pool.connected) {
    pool = null;
  }

  if (!pool) {
    // Reintentos para cuando Azure SQL serverless está en pausa
    const maxRetries = 3;
    for (let i = 0; i < maxRetries; i++) {
      try {
        pool = await sql.connect(config);
        return pool;
      } catch (err) {
        console.log(`Intento ${i + 1}/${maxRetries} de conexión falló: ${err.message}`);
        pool = null;
        if (i < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 3000));
        } else {
          throw err;
        }
      }
    }
  }
  return pool;
}

module.exports = { getPool, sql };
