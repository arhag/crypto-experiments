var secp256k1 = {
    worker: null,
    in_progress: false,
    init_complete: false,
    function_names_returned: false,
    api: {},
    result_callback: null,
    init: function(callback) {
        if(typeof(Worker) !== "undefined") 
        {
            if(this.worker == null)
            {
                secp256k1.init_complete = false;
                secp256k1.function_names_returned = false;
                secp256k1.in_progress = true;
                secp256k1.worker = new Worker("libsecp256k1.js");
                var ab = new ArrayBuffer(1);
                secp256k1.worker.postMessage(ab, [ab]);
                if (ab.byteLength) {
                    // Transferable Objects not supported.
                    // Clean up and throw error.
                    secp256k1.in_progress = false;
                    secp256k1.terminate();
                    secp256k1.worker = null;
                    throw ('Error: secp256k1.js requires Transferables Objects.');
                }
            }
            secp256k1.worker.onerror = function(error) {
                secp256k1.in_progress = false;
                secp256k1.result_callback = null;
                throw error;
            };
            secp256k1.worker.onmessage = function(event) {
                var data = event.data;
                if (data.hasOwnProperty('type'))
                {
                    if (data.type == 'init_complete')
                    {
                        secp256k1.init_complete = true;
                    }
                    else if (data.type == 'function_names')
                    {
                        secp256k1.function_names_returned = true;
                        secp256k1.api = {};
                        var function_names = data.result;
                        for (var i = 0; i < function_names.length; ++i)
                        {
                            secp256k1.api[function_names[i]] = (function(fname) {
                                return function() {
                                    var args = arguments;
                                    return new Promise(function(resolve, reject) {
                                        var callback_wrapper = (function(success_cb, error_cb) {
                                            return function(ret) {
                                                if (ret.error != undefined)
                                                {
                                                    error_cb(ret.error);
                                                }
                                                else
                                                {
                                                    success_cb(ret);
                                                }
                                            };
                                        })(resolve, reject);
                                       
                                        secp256k1.call(fname, args, callback_wrapper);
                                    });
                                };
                            })(function_names[i]);
                        }
                    }
                    
                    if (secp256k1.init_complete && secp256k1.function_names_returned)
                    {
                        secp256k1.in_progress = false;
                        secp256k1.worker.onmessage = function(event) {
                            var data = event.data;
                            var result_callback = secp256k1.result_callback;
                            secp256k1.in_progress = false;
                            secp256k1.result_callback = null;
                            if (result_callback != null && result_callback != undefined)
                            {
                                result_callback(data);
                            }
                        };
                        callback();
                    }
                }
                else
                {
                    throw "Unexpected result: " + data;
                }
            };
        } else {
            throw "Error: secp256k1.js requires Web Worker support.";
        }
    },
    call: function(operation, args, callback) {
        if (secp256k1.worker == null)
        {
            throw "secp256k1 has not yet been initialized.";
        }
        else if (secp256k1.in_progress)
        {
            throw "Operation already in progress.";
        }
        secp256k1.in_progress = true;
        secp256k1.result_callback = callback;
        secp256k1.worker.postMessage({operation: operation, args_length: args.length, args: args});
    },
    destroy: function() {
        if (secp256k1.worker != undefined)
        {
            secp256k1.call('destroy', null, function() {
                secp256k1.worker.terminate();
                secp256k1.worker = null;
                secp256k1.in_progress = false;
                secp256k1.init_complete = false;
                secp256k1.function_names_returned = false;
                secp256k1.api = {};
            });
        }
    } 
};

