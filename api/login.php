<?php
header("Access-Control-Allow-Origin: *"); // Allow all origins
header("Content-Type: application/json; charset=UTF-8"); // Set content type to JSON
header("Access-Control-Allow-Methods: POST"); // Allow POST method
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With"); // Allow headers

include_once '../config/database.php'; // Include database configuration

$database = new Database(); // Create a new database object
$db = $database->getConnection(); // Get the database connection

$data = json_decode(file_get_contents("php://input")); // Get JSON data from input

if (!empty($data->email) && !empty($data->password)) {
    $query = "SELECT id, username, email, password FROM users WHERE email = :email";
    $stmt = $db->prepare($query);

    $email = htmlspecialchars(strip_tags($data->email));
    $stmt->bindParam(":email", $email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $id = $row['id'];
        $username = $row['username'];
        $email = $row['email'];
        $password = $row['password'];

        if (password_verify($data->password, $password)) {
            http_response_code(200);
            echo json_encode(array(
                "message" => "Login successful.",
                "user" => array(
                    "id" => $id,
                    "username" => $username,
                    "email" => $email
                )
            ));
        } else {
            http_response_code(401);
            echo json_encode(array("message" => "Invalid credentials."));
        }
    } else {
        http_response_code(401);
        echo json_encode(array("message" => "Invalid credentials."));
    }
} else {
    http_response_code(400);
    echo json_encode(array("message" => "Unable to login. Data is incomplete."));
}
?>