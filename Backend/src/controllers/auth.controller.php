<?php
require_once __DIR__ . '/../models/auth.model.php';
require_once __DIR__ . '/../utils/jwt.util.php';

class AuthController {
    public static function register($data) {
        try {
            $name = $data['name'] ?? '';
            $email = $data['email'] ?? '';
            $password = $data['password'] ?? '';
            $role = $data['role'] ?? 'buyer'; // default to buyer

            if (!$name || !$email || !$password) {
                http_response_code(400);
                echo json_encode(["message" => "All fields are required"]);
                return;
            }

            $user = UserModel::findByEmail($email);
            if ($user === false) {
                throw new Exception("Error while checking user existence.");
            }
            if ($user) {
                http_response_code(409);
                echo json_encode(["message" => "Email already exists"]);
                return;
            }

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $success = UserModel::create($name, $email, $hashedPassword, $role);

            if ($success) {
                $user = UserModel::findByEmail($email);
                if ($user === false) {
                    throw new Exception("Error while fetching registered user.");
                }
                unset($user['password']); // Remove password before sending response

                echo json_encode([
                    "message" => "User registered successfully",
                    "user" => $user
                ]);

            } else {
                http_response_code(500);
                echo json_encode(["message" => "Registration failed"]);
            }
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(["message" => "Server error: " . $e->getMessage()]);
        }
    }

    public static function login($data) {
        try {
            $email = $data['email'] ?? '';
            $password = $data['password'] ?? '';

            if (!$email || !$password) {
                http_response_code(400);
                echo json_encode(["message" => "Email and password required"]);
                return;
            }

            $user = UserModel::findByEmail($email);
            if ($user === false) {
                throw new Exception("Error while fetching user.");
            }
            if (!$user || !password_verify($password, $user['password'])) {
                http_response_code(401);
                echo json_encode(["message" => "Invalid credentials"]);
                return;
            }

            unset($user['password']); // never expose password

            // generate token
            $token = generateJWT([
                'id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role']
            ]);

            // Set token in cookie
            setcookie("jwt", $token, [
                'expires' => time() + JWT_EXPIRY,
                'httponly' => true,
                'path' => '/',  // apply to all routes
                'samesite' => 'Lax', // or 'None' if using cross-site
            ]);
            echo json_encode([
                "message" => "Login successful",
                "user" => $user,
                "token" => $token,
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(["message" => "Server error: " . $e->getMessage()]);
        }
    }

    public static function me() {
        try {
            // Check if user info is set by the middleware
            if (!isset($_REQUEST['user'])) {
                http_response_code(401);
                echo json_encode(["message" => "Unauthorized"]);
                return;
            }

            $user = $_REQUEST['user'];
            unset($user['password']); // Just in case

            echo json_encode([
                "message" => "User data fetched successfully",
                "user" => $user
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(["message" => "Server error: " . $e->getMessage()]);
        }
    }
}
