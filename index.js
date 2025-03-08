const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const admin = require("firebase-admin")

// Initialize Firebase only if it hasn't been initialized already
let firebaseApp
try {
  firebaseApp = admin.app()
} catch (e) {
  const serviceAccount = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  }

  firebaseApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  })
}

const auth = admin.auth()
const db = admin.firestore()

const app = express()
app.use(cors())
app.use(express.json())

const JWT_SECRET = process.env.JWT_SECRET || "secret_key"

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]

  if (!token) {
    return res.status(401).json({ message: "Acceso denegado. Token requerido" })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch (error) {
    return res.status(401).json({ message: "Token inválido o expirado" })
  }
}

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok" })
})

app.post("/api/register", async (req, res) => {
  const { email, username, password } = req.body

  if (!email || !username || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" })
  }

  try {
    // Check if user exists
    try {
      const userRecord = await auth.getUserByEmail(email)
      if (userRecord) {
        return res.status(400).json({ message: "El email ya está registrado" })
      }
    } catch (error) {
      if (error.code !== "auth/user-not-found") {
        return res.status(500).json({ message: "Error al verificar el email", error: error.message })
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const userRecord = await auth.createUser({
      email,
      password: hashedPassword,
      displayName: username,
    })

    await db.collection("users").doc(userRecord.uid).set({
      username,
      email,
      password: hashedPassword,
    })

    res.status(201).json({
      message: "Usuario registrado correctamente",
      userId: userRecord.uid,
    })
  } catch (error) {
    res.status(500).json({ message: "Error al registrar usuario", error: error.message })
  }
})

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: "Email y contraseña son requeridos" })
  }

  try {
    const userRecord = await auth.getUserByEmail(email)
    const userDoc = await db.collection("users").doc(userRecord.uid).get()
    const userData = userDoc.data()

    const passwordMatch = await bcrypt.compare(password, userData.password)
    if (!passwordMatch) {
      return res.status(400).json({ message: "Contraseña incorrecta" })
    }

    const token = jwt.sign({ uid: userRecord.uid, email: userData.email, username: userData.username }, JWT_SECRET, {
      expiresIn: "1h",
    })

    await db.collection("users").doc(userRecord.uid).update({
      last_login: admin.firestore.FieldValue.serverTimestamp(),
    })

    res.json({ message: "Login exitoso", token })
  } catch (error) {
    return res.status(400).json({ message: "Usuario no encontrado", error: error.message })
  }
})

app.delete("/api/task/:id", verifyToken, async (req, res) => {
  const taskId = req.params.id
  const userId = req.user.uid

  try {
    const taskRef = db.collection("tasks").doc(taskId)
    const taskDoc = await taskRef.get()

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" })
    }

    if (taskDoc.data().userId !== userId) {
      return res.status(403).json({ message: "No tienes permiso para eliminar esta tarea" })
    }

    await taskRef.delete()
    res.status(200).json({ message: "Tarea eliminada correctamente" })
  } catch (error) {
    res.status(500).json({ message: "Error al eliminar la tarea", error: error.message })
  }
})

app.put("/api/task/:id", verifyToken, async (req, res) => {
  const taskId = req.params.id
  const userId = req.user.uid
  const { status } = req.body

  try {
    const taskRef = db.collection("tasks").doc(taskId)
    const taskDoc = await taskRef.get()

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" })
    }

    await taskRef.update({
      status,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    })

    res.status(200).json({ message: "Estatus de tarea actualizado correctamente" })
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar la tarea", error: error.message })
  }
})

app.get("/api/users", verifyToken, async (req, res) => {
  try {
    const usersSnapshot = await db.collection("users").get()
    const users = usersSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }))

    res.status(200).json(users)
  } catch (error) {
    res.status(500).json({ message: "Error al obtener la lista de usuarios", error: error.message })
  }
})

app.post("/api/task", verifyToken, async (req, res) => {
  const { name, description, time, status, category } = req.body
  const userId = req.user.uid

  if (!name || !status) {
    return res.status(400).json({ message: "El nombre y el estatus son obligatorios" })
  }

  try {
    const taskRef = db.collection("tasks").doc()
    await taskRef.set({
      userId,
      creatorId: userId,
      name,
      description,
      time,
      status,
      category,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    })

    res.status(201).json({
      message: "Tarea agregada correctamente",
      taskId: taskRef.id,
    })
  } catch (error) {
    res.status(500).json({ message: "Error al agregar tarea", error: error.message })
  }
})

app.get("/api/tasks", verifyToken, async (req, res) => {
  const userId = req.user.uid

  try {
    const tasksSnapshot = await db.collection("tasks").where("userId", "==", userId).get()
    const tasks = tasksSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }))

    res.status(200).json(tasks)
  } catch (error) {
    res.status(500).json({ message: "Error al obtener tareas", error: error.message })
  }
})

app.post("/api/group", verifyToken, async (req, res) => {
  const { groupName, users } = req.body
  if (!groupName || !users || users.length === 0) {
    return res.status(400).json({ message: "El nombre del grupo y los usuarios son obligatorios" })
  }

  try {
    const creatorId = req.user.uid
    const groupRef = db.collection("groups").doc()

    await groupRef.set({
      groupName,
      creatorId,
      users: [creatorId, ...users],
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    })

    res.status(201).json({
      message: "Grupo creado correctamente",
      groupId: groupRef.id,
    })
  } catch (error) {
    res.status(500).json({ message: "Error al crear el grupo", error: error.message })
  }
})

app.post("/api/groups/:groupId/add-user", verifyToken, async (req, res) => {
  const { email } = req.body
  const { groupId } = req.params

  if (!email) {
    return res.status(400).json({ message: "El correo es obligatorio" })
  }

  try {
    const userSnapshot = await db.collection("users").where("email", "==", email).get()

    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" })
    }

    const userDoc = userSnapshot.docs[0]
    const userId = userDoc.id

    const groupRef = db.collection("groups").doc(groupId)
    const groupDoc = await groupRef.get()

    if (!groupDoc.exists) {
      return res.status(404).json({ message: "Grupo no encontrado" })
    }

    const groupData = groupDoc.data()

    if (groupData.creatorId !== req.user.uid) {
      return res.status(403).json({ message: "No tienes permisos para agregar usuarios a este grupo" })
    }

    if (!groupData.users.includes(userId)) {
      await groupRef.update({
        users: [...groupData.users, userId],
      })

      return res.status(200).json({ message: "Usuario agregado correctamente" })
    } else {
      return res.status(400).json({ message: "El usuario ya está en el grupo" })
    }
  } catch (error) {
    res.status(500).json({ message: "Error al agregar usuario al grupo", error: error.message })
  }
})

app.patch("/api/groups/:groupId", verifyToken, async (req, res) => {
  const { groupId } = req.params
  const { creatorId } = req.body

  try {
    const groupRef = db.collection("groups").doc(groupId)
    await groupRef.update({ creatorId })
    res.status(200).json({ message: "El creador del grupo ha sido actualizado" })
  } catch (error) {
    res.status(500).json({ error: "No se pudo actualizar el creador del grupo" })
  }
})

app.get("/api/groups", verifyToken, async (req, res) => {
  const userId = req.user.uid

  try {
    const groupsSnapshot = await db.collection("groups").where("users", "array-contains", userId).get()
    const groups = groupsSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }))

    res.status(200).json(groups)
  } catch (error) {
    res.status(500).json({ message: "Error al obtener grupos", error: error.message })
  }
})

app.post("/api/group/:groupId/task", verifyToken, async (req, res) => {
  const groupId = req.params.groupId
  const { name, description, time, status, category, assignedUser } = req.body
  const userId = req.user.uid

  if (!name || !status || !assignedUser) {
    return res.status(400).json({ message: "El nombre, el estatus y el usuario asignado son obligatorios" })
  }
  try {
    const groupRef = db.collection("groups").doc(groupId)
    const groupDoc = await groupRef.get()
    if (!groupDoc.exists) {
      return res.status(404).json({ message: "Grupo no encontrado" })
    }
    const groupData = groupDoc.data()
    if (groupData.creatorId !== userId) {
      return res.status(403).json({ message: "Solo el creador del grupo puede crear tareas" })
    }

    const taskRef = db.collection("tasks").doc()
    await taskRef.set({
      groupId,
      userId: assignedUser,
      name,
      description,
      time,
      status,
      category,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    })

    res.status(201).json({
      message: "Tarea creada correctamente",
      taskId: taskRef.id,
    })
  } catch (error) {
    res.status(500).json({ message: "Error al crear la tarea en el grupo", error: error.message })
  }
})

// For local development
if (process.env.NODE_ENV !== "production") {
  const port = process.env.PORT || 3000
  app.listen(port, "0.0.0.0", () => {
    console.log(`Servidor escuchando en el puerto ${port}`)
  })
}

// Export for Vercel
module.exports = app

