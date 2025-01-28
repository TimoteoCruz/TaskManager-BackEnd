const express = require('express');
const app = express();

const usuarioValido = 'admin';
const passwordValida = '12345';

app.get('/login', (req, res) => {
    const { usuario, password } = req.query;  
    if (usuario === usuarioValido && password === passwordValida) {
        return res.status(200).json({
            statusCode: 200,
            intMessage: 'Bienvenido',
            data: {
                message: 'TOKEN: ASJO180SJAOASJD10'
            }
        });
    } else {
        return res.status(401).json({
            statusCode: 401,
            intMessage: 'Las credenciales no coinciden',
        });
    }
});

app.listen(3000, () => {
    console.log('Servidor corriendo');
});
