const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Conexión a MongoDB Atlas (quita las opciones deprecated)
mongoose.connect(process.env.MONGODB_URI)  // Removí useNewUrlParser y useUnifiedTopology
  .then(() => console.log('✅ Conectado a MongoDB Atlas'))
  .catch(err => {
    console.error('❌ Error de conexión a MongoDB:', err);
    process.exit(1);  // Sale del proceso si DB falla al inicio
  });

// Esquema y modelo de usuario (OK)
const usuarioSchema = new mongoose.Schema({
  usuario: { type: String, required: true, unique: true },
  contrasena: { type: String, required: true }
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Ruta base para comprobar el servidor (OK)
app.get('/', (req, res) => {
  res.send('🚀 Servidor funcionando correctamente');
});

// Registro de usuario (agrega más logging en catch)
app.post('/register', async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;
    console.log('📥 Request body en /register:', req.body);  // Debug: ve qué llega

    if (!usuario || !contrasena) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    const usuarioExistente = await Usuario.findOne({ usuario });
    if (usuarioExistente) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const salt = await bcrypt.genSalt(10);
    const contrasenaHasheada = await bcrypt.hash(contrasena, salt);

    const nuevoUsuario = new Usuario({
      usuario,
      contrasena: contrasenaHasheada
    });

    await nuevoUsuario.save();

    res.status(201).json({ mensaje: 'Registro exitoso' });
  } catch (error) {
    console.error('🚨 Error detallado en /register:', {
      message: error.message,
      stack: error.stack,
      name: error.name  // Ej. "MongoError", "ValidationError"
    });
    res.status(500).json({ 
      error: 'Error interno del servidor', 
      details: error.message  // Temporal: muestra en respuesta para debug (quita en prod)
    });
  }
});

// Inicio de sesión (mismo logging)
app.post('/login', async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;
    console.log('📥 Request body en /login:', req.body);  // Debug

    if (!usuario || !contrasena) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    const usuarioEncontrado = await Usuario.findOne({ usuario });
    if (!usuarioEncontrado) {
      return res.status(401).json({ error: 'Error en la autenticación' });
    }

    const esValida = await bcrypt.compare(contrasena, usuarioEncontrado.contrasena);
    if (!esValida) {
      return res.status(401).json({ error: 'Error en la autenticación' });
    }

    res.status(200).json({ mensaje: 'Autenticación satisfactoria' });
  } catch (error) {
    console.error('🚨 Error detallado en /login:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({ 
      error: 'Error interno del servidor', 
      details: error.message  // Temporal para debug
    });
  }
});

// 🟢 Middleware de errores GLOBAL (agrega esto NUEVO al final, antes de app.listen)
app.use((err, req, res, next) => {
  console.error('🚨 ERROR GLOBAL 500:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    body: req.body
  });
  res.status(500).json({ 
    error: 'Error interno del servidor', 
    details: process.env.NODE_ENV === 'development' ? err.message : 'Detalles ocultos'  // Solo en dev
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});