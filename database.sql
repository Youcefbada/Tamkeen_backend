CREATE DATABASE IF NOT EXISTS tamkeen;
USE tamkeen;

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  first_name VARCHAR(500),
  last_name VARCHAR(500),
  email VARCHAR(500) UNIQUE,
  password VARCHAR(500),
  phone VARCHAR(500),
  address TEXT,
  user_type VARCHAR(500),
  level_of_education VARCHAR(500),
  profile_picture VARCHAR(500),
  cv VARCHAR(500),
  certificate VARCHAR(500),
  receive_notifications BOOLEAN DEFAULT TRUE,
  notification_type VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE companies (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(500),
  email VARCHAR(500) UNIQUE,
  password VARCHAR(500),
  domain VARCHAR(500),
  size VARCHAR(500),
  website VARCHAR(500),
  wilaya VARCHAR(500),
  Commune VARCHAR(500),
  numero_commerce VARCHAR(500),
  phone VARCHAR(500),
  address TEXT,
  logo VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE training_centers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(500),
  email VARCHAR(500) UNIQUE,
  password VARCHAR(500),
  phone VARCHAR(500),
  numero_commerce VARCHAR(500),
  type VARCHAR(500),
  wilaya VARCHAR(500),
  Commune VARCHAR(500),
  speciality VARCHAR(500),
  website VARCHAR(500),
  facebook VARCHAR(500),
  instagram VARCHAR(500),
  X VARCHAR(500),
  linkedin VARCHAR(500),
  address TEXT,   
  logo VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE interests (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(500)
);

CREATE TABLE trainers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  first_name VARCHAR(500),
  last_name VARCHAR(500),
  email VARCHAR(500) UNIQUE,
  date_of_birth DATE,
  gender VARCHAR(500),
  wilaya VARCHAR(500),
  Commune VARCHAR(500),
  Street VARCHAR(500),
  passsword VARCHAR(500),
  education_level VARCHAR(500),
  interests VARCHAR(500),
  other_skill VARCHAR(500),
  profile_picture VARCHAR(500),
  certificated VARCHAR(500),
  cv VARCHAR(500),
  phone VARCHAR(500),
  specialty VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE internships (
  id INT PRIMARY KEY AUTO_INCREMENT,
  company_id INT NOT NULL,
  title VARCHAR(500),
  description TEXT,
  category_id INT,
  type VARCHAR(500),
  mode VARCHAR(500),
  duration VARCHAR(500),
  location VARCHAR(500),
  start_date DATE,
  end_date DATE,
  image VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE training_programs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  center_id INT NOT NULL,
  title VARCHAR(500),
  description TEXT,
  category_id INT,
  type VARCHAR(500),
  mode VARCHAR(500),
  duration VARCHAR(500),
  location VARCHAR(500),
  start_date DATE,
  end_date DATE,
  image VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE internship_applications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  internship_id INT NOT NULL,
  education_level VARCHAR(500),
  cv VARCHAR(500),
  certificate VARCHAR(500),
  status VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE program_applications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  training_program_id INT NOT NULL,
  education_level VARCHAR(500),
  profile_picture VARCHAR(500),
  cv VARCHAR(500),
  certificate VARCHAR(500),
  status VARCHAR(500),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_interests (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  interest_id INT NOT NULL
);

CREATE TABLE notifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  content TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE program_trainers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  trainer_id INT NOT NULL,
  training_program_id INT NOT NULL
);

CREATE TABLE tokens (
  id INT PRIMARY KEY AUTO_INCREMENT,
  token TEXT NOT NULL,
  type VARCHAR(50) NOT NULL,
  user_id INT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);