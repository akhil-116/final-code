// Function to register
function registerUser() {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    if (username.trim() === '' || password.trim() === '') {
        document.getElementById('message').innerHTML = 'Please enter both username and password.';
        return;
    }

    // Send the data to the backend (Python)
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/register', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                var data = JSON.parse(xhr.responseText);
                document.getElementById('message').innerHTML = data.message;
            } else {
                console.error('Error:', xhr.statusText);
                document.getElementById('message').innerHTML = 'An error occurred during registration.';
            }
        }
    };

    xhr.send(JSON.stringify({ username: username, password: password }));
}

// Function to login
function loginUser() {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    if (username.trim() === '' || password.trim() === '') {
        document.getElementById('message').innerHTML = 'Please enter both username and password.';
        return;
    }

    // Send the data to the backend (Python)
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/login', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                var data = JSON.parse(xhr.responseText);
                document.getElementById('message').innerHTML = data.message;

                if (data.success) {
                    // Redirect to the dashboard page after successful login
                    window.location.href = 'dashboard.html';
                }
            } else {
                console.error('Error:', xhr.statusText);
                document.getElementById('message').innerHTML = 'An error occurred during login.';
            }
        }
    };

    xhr.send(JSON.stringify({ username: username, password: password }));
}

// Function to logout
function logoutUser() {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/logout', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                window.location.href = 'login.html'; // Redirect after logout
            } else {
                console.error('Logout error:', xhr.statusText);
                alert('An error occurred during logout. Please try again.'); // Error message
            }
        }
    };

    xhr.send();
}

// Function to upload a file
function uploadFile() {
    var fileInput = document.getElementById('fileInput');
    var file = fileInput.files[0];
    if (!file) {
        alert('Please select a file.');
        return;
    }

    var formData = new FormData();
    formData.append('file', file);

    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/upload', true);
    xhr.setRequestHeader('X-File-Name', file.name);

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                alert('File uploaded successfully.');
				resetFileInputs();
            } else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred during file upload.');
            }
        }
    };

    xhr.send(formData);
}

// Function to Encrypt and Upload a file
function aesEncryptAndUpload() {
    var fileInput = document.getElementById('fileInput');
    var file = fileInput.files[0];
    
    // File validation
    if (!file) {
        alert('Please select a file.');
        return;
    }

    // Read the file content
    var reader = new FileReader();
    reader.onload = function(event) {
        var fileData = event.target.result;

        // Generate random AES key and IV
        window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 128,
            },
            true,
            ["encrypt", "decrypt"]
        ).then(function(aesKey) {
            var aesIV = new Uint8Array(16); // Fixed size for AES-GCM IV

            // Generate random IV
            window.crypto.getRandomValues(aesIV);

            // Export the AES key
            window.crypto.subtle.exportKey("raw", aesKey).then(function(exportedKey) {
                // Encrypt the file
                window.crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: aesIV
                    },
                    aesKey,
                    fileData
                ).then(function(encrypted) {
                    // Convert the exported AES key to hexadecimal string
                    var aesKeyHex = arrayBufferToHexString(exportedKey);

                    // Create form data and append encrypted file
                    var formData = new FormData();
                    formData.append('file', new Blob([encrypted], {type: file.type}));

                    // Send encrypted file asynchronously using XMLHttpRequest
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', 'https://localhost:8443/upload_encrypted', true);
                    xhr.setRequestHeader('X-File-Name', file.name);
                    xhr.setRequestHeader('X-Aes-Key', aesKeyHex);
                    xhr.setRequestHeader('X-Aes-Iv', arrayBufferToHexString(aesIV));

                    xhr.onreadystatechange = function () {
                        if (xhr.readyState == 4) {
                            if (xhr.status == 200) {
                                var message = 'File uploaded successfully.\nKeys to remember:\nAES Key: ' + aesKeyHex + '\nAES IV: ' + arrayBufferToHexString(aesIV);
                                // Check if the document object is available
                                if (window.document) {
                                    var alertWindow = window.open('', '_blank');
                                    if (alertWindow) {
                                        alertWindow.document.write('<html><head><title>Keys</title></head><body><p>' + message + '\n</p>\nPlease Remember the AES Key and IV !!!</body></html>');
                                    } else {
                                        alert('Unable to open a new window to display keys.');
                                    }
                                } else {
                                    console.error('Cannot access document object.');
                                }
                                resetFileInputs();
                            } else {
                                console.error('Error:', xhr.statusText);
                                alert('An error occurred while sending the file.');
                            }
                        }
                    };
                    xhr.send(formData);
                }).catch(function(err) {
                    console.error(err);
                    alert('Encryption failed.');
                });
            });
        }).catch(function(err) {
            console.error(err);
            alert('Failed to generate AES key.');
        });
    };
    reader.readAsArrayBuffer(file);
}

// Function to show uploaded files
function showUploadedFiles() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://localhost:8443/uploaded_files', true);

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                var uploadedFiles = JSON.parse(xhr.responseText);
                var uploadedFilesList = document.getElementById('uploadedFilesList');
                uploadedFilesList.innerHTML = '';
                uploadedFiles.forEach(function (file) {
                    var li = document.createElement('li');
                    var fileLink = document.createElement('a');
                    fileLink.textContent = file.filename + ' (user ' + file.username + ')';
                    fileLink.setAttribute('href', '/download_uploaded?filename=' + encodeURIComponent(file.filename));
                    li.appendChild(fileLink);
                    uploadedFilesList.appendChild(li);
                });
            } else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred while fetching uploaded files.');
            }
        }
    };

    xhr.send();
}

// Function to send file to user
function sendFile() {
    // Retrieve values from input fields
    var recipientUsername = document.getElementById('recipientUsername').value.trim();
    var fileToSend = document.getElementById('fileToSend').files[0];

    // Validate recipient username
    if (!recipientUsername) {
        alert('Please enter a recipient username.');
        return;
    }

    // Validate file selection
    if (!fileToSend) {
        alert('Please select a file to send.');
        return;
    }

    // Create FormData object to send file
    var formData = new FormData();
    formData.append('fileToSend', fileToSend);

    // Send file asynchronously using XMLHttpRequest
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/send_file', true);
    xhr.setRequestHeader('X-Recipient-Username', recipientUsername);
    xhr.setRequestHeader('X-File-Name', fileToSend.name);

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                alert('File sent successfully.');
            } else if (xhr.status == 400) {
                var response = JSON.parse(xhr.responseText);
                alert(response.message);
            }else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred while sending the file.');
            }
        }
    };

    xhr.send(formData);
}

// Function to encrypt file and send to other user
function sendEncryptedFile() {
    // Retrieve values from input fields
    var recipientUsername = document.getElementById('recipientUsername').value.trim();
    var fileToSend = document.getElementById('fileToSend').files[0];

    // Validate recipient username
    if (!recipientUsername) {
        alert('Please enter a recipient username.');
        return;
    }

    // Validate file selection
    if (!fileToSend) {
        alert('Please select a file to send.');
        return;
    }

    // Read the file content
    var reader = new FileReader();
    reader.onload = function(event) {
        var fileData = event.target.result;

        // Generate random AES key and IV
        window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 128,
            },
            true,
            ["encrypt", "decrypt"]
        ).then(function(aesKey) {
            var aesIV = new Uint8Array(16);
            window.crypto.getRandomValues(aesIV);

            // Export the AES key
            window.crypto.subtle.exportKey("raw", aesKey).then(function(exportedKey) {
                // Encrypt the file
                window.crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: aesIV
                    },
                    aesKey,
                    fileData
                ).then(function(encrypted) {
                    // Convert the exported AES key to hexadecimal string
                    var aesKeyHex = arrayBufferToHexString(exportedKey);

                    // Create form data and append encrypted file
                    var formData = new FormData();
                    formData.append('file', new Blob([encrypted], {type: fileToSend.type}));

                    // Send encrypted file asynchronously using XMLHttpRequest
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', 'https://localhost:8443/send_encrypted', true);
                    xhr.setRequestHeader('X-Recipient-Username', recipientUsername);
                    xhr.setRequestHeader('X-File-Name', fileToSend.name);
                    xhr.setRequestHeader('X-Aes-Key', aesKeyHex);
                    xhr.setRequestHeader('X-Aes-Iv', arrayBufferToHexString(aesIV));

                    xhr.onreadystatechange = function () {
                        if (xhr.readyState == 4) {
                            if (xhr.status == 200) {
                                var message = 'File uploaded successfully.\n Keys to remember:\nAES Key: ' + aesKeyHex + '\nAES IV: ' + arrayBufferToHexString(aesIV);
                                 // Check if the document object is available
                                if (document) {
                                    var alertWindow = window.open('', '_blank');
                                    if (alertWindow) {
                                        alertWindow.document.write('<html><head><title>Keys</title></head><body><p>' + message + '\n</p>\nPlease Remember the AES Key and IV !!!</body></html>');
                                    } else {
                                        alert('Unable to open a new window to display keys.');
                                    }
                                } else {
                                    console.error('Cannot access document object.');
                                }
                                resetFileInputs();
                            } else {
                                console.error('Error:', xhr.statusText);
                                alert('An error occurred while sending the file.');
                            }
                        }
                    };
                    xhr.send(formData);
                }).catch(function(err) {
                    console.error(err);
                    alert('Encryption failed.');
                });
            });
        }).catch(function(err) {
            console.error(err);
            alert('Failed to generate AES key.');
        });
    };
    reader.readAsArrayBuffer(fileToSend);
}

// Function to decrypt the file
function decryptSentFile() {
    var fileInput = document.getElementById('fileToSend');
    var file = fileInput.files[0];

    // Get AES key and IV from user input fields
    var aesKeyInput = document.getElementById('aesKey');
    var aesIVInput = document.getElementById('aesIv');

    if (!file || !aesKeyInput || !aesIVInput) {
        alert('Please enter AES key, AES IV, and select a file.');
        return;
    }

    // Create form data and append file
    var formData = new FormData();
    formData.append('file', file);

    // Send XMLHttpRequest to server for decryption
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://localhost:8443/decrypt_sent_file', true);
    xhr.setRequestHeader('X-File-Name', file.name);
    xhr.setRequestHeader('Aes-Key', aesKeyInput.value);
    xhr.setRequestHeader('Aes-Iv', aesIVInput.value);
    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                // File decrypted successfully, initiate download
                var blob = new Blob([xhr.response], { type: file.type });
                var url = window.URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = file.name;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
            } else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred during file decryption.');
            }
        }
    };
    xhr.responseType = 'blob'; // Set response type to blob for downloading file
    xhr.send(formData);
}
// Function to show sent files
function showSentFiles() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://localhost:8443/sent_files', true);

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                var sentFiles = JSON.parse(xhr.responseText);
                var sentFilesList = document.getElementById('sentFilesList');
                sentFilesList.innerHTML = '';
                sentFiles.forEach(function (file) {
                    var li = document.createElement('li');
                    li.textContent = file;
                    sentFilesList.appendChild(li);
                });
            } else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred while fetching sent files.');
            }
        }
    };

    xhr.send();
}

// Function to show received files
function showReceivedFiles() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://localhost:8443/received_files', true);

    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                var receivedFiles = JSON.parse(xhr.responseText);
                var receivedFilesList = document.getElementById('receivedFilesList');
                receivedFilesList.innerHTML = '';
                receivedFiles.forEach(function (file) {
                    var li = document.createElement('li');
                    var fileLink = document.createElement('a');
                    fileLink.textContent = file.filename + ' (from: ' + file.sender + ')';
                    fileLink.setAttribute('href', '/download?filename=' + encodeURIComponent(file.filename));
                    li.appendChild(fileLink);
                    receivedFilesList.appendChild(li);
                });
            } else {
                console.error('Error:', xhr.statusText);
                alert('An error occurred while fetching received files.');
            }
        }
    };

    xhr.send();
}

function arrayBufferToHexString(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), function(x) {
        return ('00' + x.toString(16)).slice(-2);
    }).join('');
}

function resetFileInputs() {
    document.getElementById('fileInput').value = '';
    document.getElementById('fileToSend').value = '';
    document.getElementById('recipientUsername').value = '';
}

function hexStringToUint8Array(hexString) {
    var bytes = [];
    for (var i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Utility function to convert ArrayBuffer to hexadecimal string
function bufferToHexString(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

// Function to toggle VPN connection
function toggleVPN() {
    var vpnSwitch = document.getElementById('vpnSwitch');
    var isChecked = vpnSwitch.checked;

    if (isChecked) {
        connectVPN();
    } else {
        disconnectVPN();
    }
}

// Function to connect to VPN
function connectVPN() {
    // Create a new XMLHttpRequest object
    var xhr = new XMLHttpRequest();
    
    // Define the request method and endpoint
    xhr.open('POST', 'https://localhost:8443/connect_vpn', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    
    // Set up event listeners to handle response
    xhr.onload = function() {
        if (xhr.status === 200) {
            // VPN connected successfully, display message
            document.getElementById('vpnStatusMessage').innerText = 'VPN connected successfully.';
            console.log('VPN connected successfully.');
            
            // Set a timeout to remove the message after 5 seconds
            setTimeout(() => {
                document.getElementById('vpnStatusMessage').innerText = ''; // Clear the message
            }, 5000); // 5000 milliseconds = 5 seconds
        } else {
            console.error('Failed to connect to VPN.');
        }
    };
    
    // Send the request
    xhr.send();
}


// Function to disconnect from VPN
function disconnectVPN() {
    // Create a new XMLHttpRequest object
    var xhr = new XMLHttpRequest();
    
    // Define the request method and endpoint
    xhr.open('POST', '/disconnect_vpn', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    
    // Set up event listeners to handle response
    xhr.onload = function() {
        if (xhr.status === 200) {
            // VPN disconnected successfully, display message
            document.getElementById('vpnStatusMessage').innerText = 'VPN is Necessary please connect again.';
            
            // Set a timeout to remove the message after 5 seconds
            setTimeout(() => {
                document.getElementById('vpnStatusMessage').innerText = ''; // Clear the message
            }, 5000); // 5000 milliseconds = 5 seconds
        } else {
            console.error('Failed to disconnect from VPN.');
        }
    };
    
    // Send the request
    xhr.send();
}
