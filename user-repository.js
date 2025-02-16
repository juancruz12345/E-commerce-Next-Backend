import { createClient } from "@libsql/client";
import bcryptjs from "bcryptjs";
import dotenv from 'dotenv'
import crypto from 'node:crypto' 

dotenv.config()

if (!process.env.DB_URL || !process.env.DB_TOKEN) {
  throw new Error("Missing environment variables");
}

const db = createClient({
    url:process.env.DB_URL,
    authToken: process.env.DB_TOKEN
})



export class UserRepository{

  static async create({username,password,email}){

    Validation.username(username)
    Validation.password(password)

    const hashedPassword = await bcryptjs.hash(password,10)
    const id = crypto.randomUUID()
    

    const userExist = await db.execute({
      sql:'SELECT * FROM users WHERE username = :username',
      args: {username}
   })
   if(userExist.rows.length>0){
    
    throw new Error('An account with that username already exists.')
   }
   if(password.length<6){
    
    throw new Error('The password must contain at least 6 characters')
   }
   
        const user = await db.execute({
          sql: 'INSERT INTO users (username, password, email) VALUES (:username, :hashedPassword, :email)',
          args: {username, hashedPassword, email}
        })
        
        return user.lastInsertRowid.toString()
       

}


    static async login({username,password}){

      Validation.username(username)
      Validation.password(password)
   
 
      const user = await db.execute({
        sql:'SELECT * FROM users WHERE username = :username',
        args: {username}
     })
     
      if(user.rows.length===0) throw new Error('The username is not registered')
      const isValid = await bcryptjs.compare(password, user.rows[0].password)
      if(!isValid) throw new Error('The password is not valid')
        
      if(user.rows[0].verificado!==1){
        throw new Error('The user is not verified')
      }

      const {password: _, ...publicUser} = user.rows[0]
      return publicUser
    

    } 
    
   
}

class Validation{
    static username(username){
        if(typeof username !== 'string')throw new Error('username debe ser tipo string')
        if(username.length<3)throw new Error('username debe tener almenos 3 letras')
    }
    static password(password){
        if(typeof password !== 'string')throw new Error('el password debe ser un string')
        if(password.length<6)throw new Error('el password debe contener al menos 6 caracteres')
    }
}