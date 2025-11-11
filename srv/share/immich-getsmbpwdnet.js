//
// SMB PWD NET: Test user password OR Change user old new
//
// Change YOURDOMAINNAME and if necessary HOST address [host.containers.internal] and PORT [9445]
//

module.exports = { 

// check if domain indicate a smb user
domain: function(domain) {
    if (domain.split("@").pop() == "YOURDOMAINNAME") {
        return true;
    }
    return false;
},

// validate email & password
validate: function(userMail, password) {
    const testResult = new Promise ((resolve, reject) => {

    var net = require('net');
    var client = new net.Socket();

    var stat = Buffer.from('');
    const user = userMail.split("@").shift();

    client.connect(9445 /* port */, 'host.containers.internal' /* host */, function() {
    //console.log('Connected');
        client.write("Test\n" + user + "\n" + password + "\n");
    });

    client.on('data', function(data) {
    //console.log('Received: ' + data);
        if (data && data.byteLength > 0) {
            stat = Buffer.concat([stat, data]);
        }
    });

    client.on('close', function() {
    //console.log('Connection closed');
        client.destroy();
        stat = stat.toString().trim();
        resolve(stat);
    });
    });

    return testResult.then();
},

// change password
change: function (userMail, password, newPassword) {
    const changeResult = new Promise ((resolve, reject) => {

    var net = require('net');
    var client = new net.Socket();

    var stat = Buffer.from('');
    const user = userMail.split("@").shift();

    client.connect(9445 /* port */, 'host.containers.internal' /* host */, function() {
    //console.log('Connected');
        client.write("Change\n" + user + "\n" + password + "\n" + newPassword + "\n");
    });

    client.on('data', function(data) {
    //console.log('Received: ' + data);
        if (data && data.byteLength > 0) {
            stat = Buffer.concat([stat, data]);
        }
    });

    client.on('close', function() {
    //console.log('Connection closed');
        client.destroy();
        stat = stat.toString().trim();
        resolve(stat);
    });
    });

    return changeResult.then();
}

}
