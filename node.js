const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./firebaseConfig/serviceAccountKey.json'); 

// Inicializar Firebase
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const auth = admin.auth();
const db = admin.firestore();

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = "secret_key"; 

app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    try {
        const userRecord = await auth.getUserByEmail(email);
        if (userRecord) {
            return res.status(400).json({ message: 'El email ya está registrado' });
        }
    } catch (error) {
        if (error.code !== 'auth/user-not-found') {
            return res.status(500).json({ message: 'Error al verificar el email', error: error.message });
        }
    }
    

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        // Crear el usuario en Firebase Authentication
        const userRecord = await auth.createUser({
            email,
            password: hashedPassword,
            displayName: username
        });

        // Guardar el usuario en la colección
        await db.collection('users').doc(userRecord.uid).set({
            username,
            email,
            password: hashedPassword,
        });

        res.status(201).json({
            message: 'Usuario registrado correctamente',
            userId: userRecord.uid
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al registrar usuario', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email y contraseña son requeridos' });
    }

    try {
        // Buscar al usuario en Firebase
        const userRecord = await auth.getUserByEmail(email);
        
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        const userData = userDoc.data();

        const passwordMatch = await bcrypt.compare(password, userData.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        // Generar JWT con expiración de 10 minutos
        const token = jwt.sign(
            { email: userData.email, username: userData.username },
            JWT_SECRET,
            { expiresIn: '10m' }
        );

        // Actualizar la fecha de último login
        await db.collection('users').doc(userRecord.uid).update({
            last_login: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Login exitoso', token });
    } catch (error) {
        return res.status(400).json({ message: 'Usuario no encontrado', error: error.message });
    }
});

app.post('/task', async (req, res) => {
    const { name, description, time, status, category } = req.body;

    if (!name || !status) {
        return res.status(400).json({ message: 'El nombre y el estatus son obligatorios' });
    }

    try {
        const taskRef = db.collection('tasks').doc(); 
        await taskRef.set({
            name,
            description,
            time,
            status,
            category,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message: "Tarea agregada correctamente",
            taskId: taskRef.id
        });

    } catch (error) {
        res.status(500).json({ message: "Error al agregar tarea", error: error.message });
    }
});

app.listen(3000, () => {
    console.log('Servidor corriendo en http://localhost:3000');
});
