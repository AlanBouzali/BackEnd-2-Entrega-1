# Proyecto Backend E-commerce

Este proyecto toma como base la entrega final de Backend 1 en el cual se desarrolló un Servidor Backend para un e-commerce con persistencia en MONGODB. El mismo posee los siguientes Endpoints:

## Products
- **Devolver todos los Productos** - GET `http://localhost:8080/api/products/`
- **Devolver Producto por ID** - GET `http://localhost:8080/api/products/:pid`
- **Agregar Producto** - POST `http://localhost:8080/api/products/`
- **Actualizar Producto** - PUT `http://localhost:8080/api/products/:pid`
- **Borrar Producto** - DELETE `http://localhost:8080/api/products/:pid`

## Carts
- **Agregar Cart** - POST `http://localhost:8080/api/carts/`
- **Devolver Cart por ID** - GET `http://localhost:8080/api/carts/:cid`
- **Agregar Producto por ID a Cart por ID** - POST `http://localhost:8080/api/carts/:cid/products/:pid`
- **Borrar Productos de Cart especifico** - DELETE `http://localhost:8080/api/carts/:cid/products/:pid`
- **Actualizar Cart por ID** - PUT `http://localhost:8080/api/carts/:cid`
- **Actualizar quantity de prod por Id y ID de cart** - PUT `http://localhost:8080/api/carts/:cid/products/:pid`
- **Borrar todos los Productos del Cart** - DELETE `http://localhost:8080/api/carts/:cid`

## Estructura del Proyecto
El proyecto se encuentra dividido en capas:
- **Server**
- **Routes**
- **Controllers**
- **Services**
- **DAOs**

## Desarrollo de Entrega Final Backend 2
Tomando la base antes mencionada se agrega:
- Autenticación y Autorización para los Endpoints que indica la entrega
- Uso de Estrategias con Passport
- Uso de Middlewares varios
- Uso de DTOs
- Uso de JsonWebToken
- Uso de Cookies
- Uso de Mailing (para el registro)

## Endpoints adicionales
- **Registro de nuevos Usuarios** - POST `http://localhost:8080/api/auth/register`
- **Login de Usuario** - POST `http://localhost:8080/api/auth/login`
- **Logout de Usuario** - POST `http://localhost:8080/api/auth/logout`
- **Current User** - GET `http://localhost:8080/api/auth/current`
- **Cart Purchase** - GET `http://localhost:8080/api/carts/:cid/purchase`

## Variables de Entorno
Se sube archivo `.envTest` para completar variables de entorno de:
- MONGO ATLAS
- JSON WEB TOKEN
- MAILING
