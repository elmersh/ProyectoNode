/**
 * SecureFeedback S.A. - Servidor Principal
 * Aplicación de Registro Seguro de Usuarios
 *
 * Controles de seguridad implementados:
 * - Variables de entorno para credenciales (dotenv)
 * - Helmet para headers de seguridad
 * - Validación y sanitización de entradas (express-validator + xss-filters)
 * - Consultas parametrizadas (mssql)
 * - Protección contra SQL Injection y XSS
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const { getPool } = require('./db');
const userRoutes = require('./routes/users');

const app = express();
const PORT = process.env.PORT || 8080;

// ===== MIDDLEWARE DE SEGURIDAD =====

// Helmet: Configura headers HTTP de seguridad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS configurado
app.use(cors());

// Parsear JSON y form data con límite de tamaño
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// ===== RUTAS =====
app.use('/api/users', userRoutes);

// Ruta principal - Servir la SPA
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check para Azure
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ===== INICIALIZACIÓN =====
async function startServer() {
  try {
    // Inicializar conexión a la base de datos
    await getPool();
    console.log('✅ Conexión a Azure SQL Database establecida');

    // Crear tabla si no existe
    const pool = await getPool();
    await pool.request().query(`
      IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='usuarios' AND xtype='U')
      CREATE TABLE usuarios (
        id INT IDENTITY(1,1) PRIMARY KEY,
        nombre NVARCHAR(100) NOT NULL,
        apellido NVARCHAR(100) NOT NULL,
        email NVARCHAR(255) NOT NULL UNIQUE,
        telefono NVARCHAR(20),
        pais NVARCHAR(100),
        fecha_registro DATETIME DEFAULT GETDATE()
      )
    `);
    console.log('✅ Tabla de usuarios verificada/creada');

    app.listen(PORT, () => {
      console.log(`🚀 Servidor SecureFeedback corriendo en puerto ${PORT}`);
      console.log(`📋 Entorno: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Error al iniciar el servidor:', error.message);
    // En producción, intentar iniciar sin DB para que Azure pueda hacer health checks
    if (process.env.NODE_ENV === 'production') {
      app.listen(PORT, () => {
        console.log(`⚠️ Servidor iniciado en puerto ${PORT} (sin conexión a DB)`);
      });
    }
  }
}

startServer();
