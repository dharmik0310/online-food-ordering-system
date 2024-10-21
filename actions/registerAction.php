<?php
session_start();
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    header("Location: ../index.php");
}
include_once '../utils/conn.php';
include_once '../utils/input_validate.php';
header('Access-Control-Allow-Methods: POST');

// Function to validate the address
function validateAddress($address) {
    // Check if the address is at least 10 characters long
    if (strlen($address) < 30) {
        return true;
    }
    // Check for valid characters: letters, numbers, spaces, commas, periods, apostrophes, and hyphens
    if (!preg_match("/^[a-zA-Z0-9\s,.'-]+$/", $address)) {
        return false;
    }
    return true;
}

if (isset($_POST['register'])) {
    $name = $_POST['fullname'];
    $email = htmlspecialchars($_POST['email']);
    $mobile = htmlspecialchars($_POST['mobile']);
    $password = htmlspecialchars($_POST['password']);
    $cpass = htmlspecialchars($_POST['cpassword']);
    $address = htmlspecialchars($_POST['address']);

    // Validate the email
    if (validateEmail($email)) {
        // Validate the password
        if (valiatePassword($password, $cpass)) {
            // Validate the mobile number
            if (validMobile($mobile)) {
                // Validate the address
                if (validateAddress($address)) {
                    // Check if the user already exists in the database
                    if (!checkRecordExistsinDatabase($conn, $email, $mobile)) {
                        // Hash the password
                        $hash = password_hash($password, PASSWORD_BCRYPT);

                        // Prepare the statement to insert the new user
                        $STM = $conn->prepare("INSERT INTO users(fullname, email, mobile, password, address) VALUES(?, ?, ?, ?, ?)");
                        $STM->bind_param("sssss", $name, $email, $mobile, $hash, $address);

                        // Execute the statement
                        if ($STM->execute()) {
                            // Redirect to the login page on success
                            header("Location: ../pages/login.php");
                        } else {
                            // Redirect with an error if the registration fails
                            redirectWithError($_SERVER['HTTP_REFERER'], 'Registration unsuccessful! Please try again!');
                        }
                    } else {
                        // Redirect with an error if the user already exists
                        redirectWithError($_SERVER['HTTP_REFERER'], 'User already exists! Try a different email');
                    }
                } else {
                    // Redirect with an error if the address is invalid
                    redirectWithError($_SERVER['HTTP_REFERER'], 'Invalid address! Please enter a valid full address');
                }
            } else {
                // Redirect with an error if the mobile number is invalid
                redirectWithError($_SERVER['HTTP_REFERER'], 'Mobile number is invalid! Please enter a valid phone number');
            }
        } else {
            // Redirect with an error if the passwords do not match or are too short
            redirectWithError($_SERVER['HTTP_REFERER'], 'Password is not long enough! Please re-enter a longer password');
        }
    } else {
        // Redirect with an error if the email is invalid
        redirectWithError($_SERVER['HTTP_REFERER'], 'Invalid email! Please enter a valid email');
    }
}
?>
