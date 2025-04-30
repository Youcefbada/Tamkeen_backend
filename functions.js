import mysql2 from "mysql2"
import dotenv from 'dotenv'
dotenv.config()
const pool = mysql2.createPool({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'tamkeen'
}).promise()
export async function get_training_centers_name(){
    const [rows] = await pool.query(`
        Select name
        from training_centers
        `);
    return rows
}
export async function get_companies_name(){
    const [rows] = await pool.query(`
        Select name
        from companies
        `);
    return rows
}