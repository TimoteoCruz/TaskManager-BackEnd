const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const admin = require('firebase-admin');
const serviceAccount = require('./firebaseConfig/serviceAccountKey.json'); 

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const auth = admin.auth();
const db = admin.firestore();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "secret_key"; 

// Middleware para verificar el token y obtener el usuario autenticado
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Formato: "Bearer <token>"

    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado. Token requerido' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Guarda la información del usuario en la request
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Token inválido o expirado' });
    }
};

// Registro de usuario
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

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const userRecord = await auth.createUser({
            email,
            password: hashedPassword,
            displayName: username
        });

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

// Login de usuario
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email y contraseña son requeridos' });
    }

    try {
        const userRecord = await auth.getUserByEmail(email);
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        const userData = userDoc.data();

        const passwordMatch = await bcrypt.compare(password, userData.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        const token = jwt.sign(
            { uid: userRecord.uid, email: userData.email, username: userData.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        await db.collection('users').doc(userRecord.uid).update({
            last_login: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Login exitoso', token });
    } catch (error) {
        return res.status(400).json({ message: 'Usuario no encontrado', error: error.message });
    }
});

// Eliminar una tarea por ID
app.delete('/task/:id', verifyToken, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.uid; // Usuario autenticado

    try {
        const taskRef = db.collection('tasks').doc(taskId);
        const taskDoc = await taskRef.get();

        if (!taskDoc.exists) {
            return res.status(404).json({ message: 'Tarea no encontrada' });
        }

        if (taskDoc.data().userId !== userId) {
            return res.status(403).json({ message: 'No tienes permiso para eliminar esta tarea' });
        }

        await taskRef.delete();
        res.status(200).json({ message: 'Tarea eliminada correctamente' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la tarea', error: error.message });
    }
});


app.put('/task/:id', verifyToken, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.uid; // Usuario autenticado
    const { status } = req.body;

    try {
        const taskRef = db.collection('tasks').doc(taskId);
        const taskDoc = await taskRef.get();

        if (!taskDoc.exists) {
            return res.status(404).json({ message: 'Tarea no encontrada' });
        }

        const taskData = taskDoc.data();

        // Actualizar el estatus
        await taskRef.update({
            status,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: 'Estatus de tarea actualizado correctamente' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la tarea', error: error.message });
    }
});


app.get('/users', verifyToken, async (req, res) => {
    try {
        const usersSnapshot = await db.collection('users').get();
        const users = usersSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        console.log("Usuarios obtenidos:", users); // Verifica en la consola

        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la lista de usuarios', error: error.message });
    }
});


// Crear una tarea asociada al usuario autenticado
app.post('/task', verifyToken, async (req, res) => {
    const { name, description, time, status, category } = req.body;
    const userId = req.user.uid; // Obtener el UID del usuario autenticado

    if (!name || !status) {
        return res.status(400).json({ message: 'El nombre y el estatus son obligatorios' });
    }

    try {
        const taskRef = db.collection('tasks').doc();
        await taskRef.set({
            userId,  // Relación con el usuario asignado
            creatorId: userId, // Ahora el creador es el mismo que el usuario asignado
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


/*// Obtener las tareas del usuario autenticado
app.get('/tasks', verifyToken, async (req, res) => {
    const userId = req.user.uid;

    try {
        const tasksSnapshot = await db.collection('tasks').where('userId', '==', userId).get();
        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        res.status(200).json(tasks);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener tareas", error: error.message });
    }
});*/

// Obtener las tareas y grupos del usuario autenticado
app.get('/tasks', verifyToken, async (req, res) => {
    const userId = req.user.uid;


    try {
        // Obtener los grupos a los que pertenece el usuario
        const groupsSnapshot = await db.collection('groups')
            .where('users', 'array-contains', userId)
            .get();

        if (groupsSnapshot.empty) {
            return res.status(404).json({ message: 'No se encontraron grupos para este usuario.' });
        }
        //  Recoger los groupIds de los grupos
        const groupIds = groupsSnapshot.docs.map(doc => doc.id);
        //  Obtener las tareas asociadas a esos grupos
        const tasksSnapshot = await db.collection('tasks')
            .where('groupId', 'in', groupIds)
            .get();
        // Obtener las tareas
        const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        //  Preparar la respuesta con grupos y tareas
        const groups = groupsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        res.status(200).json({ groups, tasks });
    } catch (error) {
        res.status(500).json({ message: "Error al obtener grupos y tareas", error: error.message });
    }
});

// Crear un grupo
app.post('/group', verifyToken, async (req, res) => {
    const { groupName, users } = req.body; 
    if (!groupName || !users || users.length === 0) {
        return res.status(400).json({ message: 'El nombre del grupo y los usuarios son obligatorios' });
    }

    try {
        const creatorId = req.user.uid;
        const groupRef = db.collection('groups').doc();
        
        await groupRef.set({
            groupName,
            creatorId,
            users: [creatorId, ...users], 
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message: 'Grupo creado correctamente',
            groupId: groupRef.id
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear el grupo', error: error.message });
    }
});

// Obtener los grupos a los que pertenece el usuario autenticado
app.get('/groups', verifyToken, async (req, res) => {
    const userId = req.user.uid;

    try {
        const groupsSnapshot = await db.collection('groups').where('users', 'array-contains', userId).get();
        const groups = groupsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.status(200).json(groups);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener grupos', error: error.message });
    }
});

// Crear una tarea en un grupo (solo el creador puede hacerlo)
app.post('/group/:groupId/task', verifyToken, async (req, res) => {
    const groupId = req.params.groupId;
    const { name, description, time, status, category, assignedUser } = req.body;
    const userId = req.user.uid;

    if (!name || !status || !assignedUser) {
        return res.status(400).json({ message: 'El nombre, el estatus y el usuario asignado son obligatorios' });
    }
    try {
        const groupRef = db.collection('groups').doc(groupId);
        const groupDoc = await groupRef.get();
        if (!groupDoc.exists) {
            return res.status(404).json({ message: 'Grupo no encontrado' });
        }
        const groupData = groupDoc.data();
        if (groupData.creatorId !== userId) {
            return res.status(403).json({ message: 'Solo el creador del grupo puede crear tareas' });
        }

        const taskRef = db.collection('tasks').doc();
        await taskRef.set({
            groupId,
            userId: assignedUser,  
            name,
            description,
            time,
            status,
            category,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({
            message: "Tarea creada correctamente",
            taskId: taskRef.id
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la tarea en el grupo', error: error.message });
    }
});
app.get('/group/:groupId/tasks', verifyToken, async (req, res) => {
    const groupId = req.params.groupId;
    const userId = req.user.uid;

    try {
        const groupRef = db.collection('groups').doc(groupId);
        const groupDoc = await groupRef.get();

        if (!groupDoc.exists) {
            return res.status(404).json({ message: 'Grupo no encontrado' });
        }

        const groupData = groupDoc.data();

        if (!groupData.users.includes(userId)) {
            return res.status(403).json({ message: 'No tienes permiso para ver las tareas de este grupo' });
        }

        const tasksSnapshot = await db.collection('tasks')
            .where('groupId', '==', groupId)
            .where('userId', '==', userId) 
            .get();

        if (tasksSnapshot.empty) {
            return res.status(404).json({ message: 'No se encontraron tareas para este usuario en el grupo' });
        }

        const tasks = tasksSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        const tasksByStatus = tasks.reduce((acc, task) => {
            if (!acc[task.status]) {
                acc[task.status] = [];
            }
            acc[task.status].push(task);
            return acc;
        }, {});

        res.status(200).json(tasksByStatus);

    } catch (error) {
        console.error("Error al obtener las tareas:", error);  
        res.status(500).json({ message: 'Error al obtener tareas', error: error.message });
    }
});



app.listen(3000, () => {
    console.log('Servidor corriendo en http://localhost:3000');
});
