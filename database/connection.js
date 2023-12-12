const mysql = require('mysql2');

// Create a connection pool
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'task_one',
});
connection.connect((error)=>{
  if(error){
   console.log(error);
  } else {
   console.log('Connected!')
  }
})

module.exports = connection;
