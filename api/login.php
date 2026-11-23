<?php
require_once 'db_connect.php';

$data = json_decode(file_get_contents('php://input'), true);
$email = strtolower(trim($data['email'] ?? ''));
$password = $data['password'] ?? '';

$stmt = $conn->prepare('SELECT name, email, password_hash, role FROM users WHERE email = ?');
$stmt->bind_param('s', $email);
$stmt->execute();
$res = $stmt->get_result();
$user = $res->fetch_assoc();

if (!$user || !password_verify($password, $user['password_hash'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid email or password']);
    exit;
}

echo json_encode([
    'success' => true,
    'name' => $user['name'],
    'email' => $user['email'],
    'role' => $user['role']
]);
$stmt->close();
$conn->close();