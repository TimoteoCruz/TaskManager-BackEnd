const mysql = require('mysql2');

const db = mysql.createConnection({
    host: 'localhost',  
    user: 'root',      
    password: 'algebra31',
    database: 'usuarios'  
});

db.connect((err) => {
    if (err) {
        console.error('Error al conectar a MySQL: ' + err.stack);
        return;
    }
    console.log('Conexión establecida a la BD ');
});

module.exports = db;
