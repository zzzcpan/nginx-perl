
var http  = require ('http'), 
    redis = require ('redis');

var redisClient = redis.createClient ();


var srv = http.createServer (function (req, res) {

    if (req.url == '/') {

        res.writeHead (200, {'Content-Type': 'text/plain'});
        res.end ("hello\n");

    } else if (req.url == '/single') {

        redisClient.get ('mykey', function (err, reply) {

            res.writeHead (200, {'Content-Type': 'text/plain'});
            res.end (reply.toString () + "\n");

        });
    } else if (req.url == '/multi') {

        var cnt = 10;

        for (var i = cnt; i > 0; i--) {

            redisClient.get ('mykey', function (err, reply) {

                if (--cnt == 0) {
                    res.writeHead (200, {'Content-Type': 'text/plain'});
                    res.end (reply.toString () + "\n");
                }
            });
        }
    } else {

        res.writeHead (404, {'Content-Type': 'text/plain'});
        res.end ("not found\n");
    }

});

srv.listen (55555, "0.0.0.0");


console.log ( "                                  \n" + 
              "                                  \n" + 
              "    Listening on *:55555          \n" +
              "        http://127.0.0.1:55555/   \n" +
              "                                  \n" + 
              "                                  "    );

