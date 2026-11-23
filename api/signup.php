<?php
require_once 'db_connect.php';

$data = json_decode(file_get_contents('php://input'), true);
$name = trim($data['name'] ?? '');
$email = strtolower(trim($data['email'] ?? ''));
$password = $data['password'] ?? '';
$role = $data['role'] ?? '';

if (!$name || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8 || !in_array($role, ['teacher','student'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

// check existing
$stmt = $conn->prepare('SELECT id FROM users WHERE email = ?');
$stmt->bind_param('s', $email);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    http_response_code(409);
    echo json_encode(['error' => 'Email already exists']);
    exit;
}
$stmt->close();

$hash = password_hash($password, PASSWORD_DEFAULT);
$stmt = $conn->prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)');
$stmt->bind_param('ssss', $name, $email, $hash, $role);
if ($stmt->execute()) {
    echo json_encode(['success' => true, 'name' => $name, 'email' => $email, 'role' => $role]);
} else {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to create account']);
}
$stmt->close();
$conn->close();