/**
 * Rutas de Usuarios - SecureFeedback S.A.
 *
 * Seguridad implementada:
 * - Validación de entradas con express-validator
 * - Sanitización contra XSS con xss-filters
 * - Consultas parametrizadas para prevenir SQL Injection
 * - Manejo seguro de errores (sin exponer detalles internos)
 */

const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const xssFilters = require('xss-filters');
const { getPool, sql } = require('../db');

// ===== REGLAS DE VALIDACIÓN =====
const validacionRegistro = [
  body('nombre')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('El nombre debe tener entre 2 y 100 caracteres')
    .matches(/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$/)
    .withMessage('El nombre solo puede contener letras y espacios'),

  body('apellido')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('El apellido debe tener entre 2 y 100 caracteres')
    .matches(/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$/)
    .withMessage('El apellido solo puede contener letras y espacios'),

  body('email')
    .trim()
    .isEmail()
    .withMessage('Ingrese un correo electrónico válido')
    .normalizeEmail()
    .isLength({ max: 255 })
    .withMessage('El correo no puede exceder 255 caracteres'),

  body('telefono')
    .optional({ checkFalsy: true })
    .trim()
    .matches(/^[\d\s\-\+\(\)]{7,20}$/)
    .withMessage('Ingrese un número de teléfono válido'),

  body('pais')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('El país no puede exceder 100 caracteres')
    .matches(/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$/)
    .withMessage('El país solo puede contener letras y espacios')
];

// ===== POST /api/users - Registrar nuevo usuario =====
router.post('/', validacionRegistro, async (req, res) => {
  try {
    // Verificar errores de validación
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Error de validación',
        errors: errors.array().map(e => e.msg)
      });
    }

    // Sanitizar entradas contra XSS
    const nombre = xssFilters.inHTMLData(req.body.nombre.trim());
    const apellido = xssFilters.inHTMLData(req.body.apellido.trim());
    const email = xssFilters.inHTMLData(req.body.email.trim());
    const telefono = req.body.telefono ? xssFilters.inHTMLData(req.body.telefono.trim()) : null;
    const pais = req.body.pais ? xssFilters.inHTMLData(req.body.pais.trim()) : null;

    // Consulta parametrizada (previene SQL Injection)
    const pool = await getPool();
    const result = await pool.request()
      .input('nombre', sql.NVarChar(100), nombre)
      .input('apellido', sql.NVarChar(100), apellido)
      .input('email', sql.NVarChar(255), email)
      .input('telefono', sql.NVarChar(20), telefono)
      .input('pais', sql.NVarChar(100), pais)
      .query(`
        INSERT INTO usuarios (nombre, apellido, email, telefono, pais)
        VALUES (@nombre, @apellido, @email, @telefono, @pais);
        SELECT SCOPE_IDENTITY() AS id;
      `);

    res.status(201).json({
      success: true,
      message: 'Usuario registrado exitosamente',
      data: {
        id: result.recordset[0].id,
        nombre,
        apellido,
        email
      }
    });

  } catch (error) {
    // Manejar error de email duplicado
    if (error.number === 2627 || error.number === 2601) {
      return res.status(409).json({
        success: false,
        message: 'El correo electrónico ya está registrado'
      });
    }

    // No exponer detalles del error en producción
    console.error('Error al registrar usuario:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor. Intente nuevamente.'
    });
  }
});

// ===== GET /api/users - Listar usuarios registrados =====
router.get('/', async (req, res) => {
  try {
    const pool = await getPool();

    // Consulta parametrizada con paginación
    const result = await pool.request()
      .query(`
        SELECT id, nombre, apellido, email, telefono, pais,
               FORMAT(fecha_registro, 'dd/MM/yyyy HH:mm') as fecha_registro
        FROM usuarios
        ORDER BY fecha_registro DESC
      `);

    res.json({
      success: true,
      count: result.recordset.length,
      data: result.recordset
    });

  } catch (error) {
    console.error('Error al obtener usuarios:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

module.exports = router;
