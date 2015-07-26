if (typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope)
{
// This means we are in a Web Worker (which is required)

var libsecp256k1 = {
    function_arguments: {
        // Each function name (without secp256k_ prefix) maps to an array with length equal to number of arguments the function takes.
        // The absolute value of each item in the array describes the minimum number of bytes needed in buffer for the corresponding argument.
        // If an argument is not passed by pointer and is a basic type (int, float, double), the number of bytes needed should be 0.
        // If the argument is a pointer to the context, the number of bytes needed should be 0 since this.context has already allocated it.
        // If the number is negative, it means that argument is also an output (only applies to argument that need buffer space).
        // All sizes are rounded up to nearest integer divisible by 4 for alignment reasons .

        'secp256k1_ecdsa_recover_compact': [0, 32, 64, -33 /* assuming compressed public keys only */, -4, 0, 0],
        'secp256k1_ecdsa_sign_compact': [0, 32, -64, 32, 0, 0, -4],
        'secp256k1_ec_pubkey_create': [0, -33, -4, 32, 0],
        'secp256k1_ec_seckey_verify': [0, 32],
        'secp256k1_scalar_set_b32': [-32, 32, -4],
    },
    init: function() {
        // First alias important Module functions to workaround Closure issues
        this.m.cwrap    = Module['cwrap'];
        this.m.malloc   = Module['_malloc'];
        this.m.free     = Module['_free'];
        this.m.getValue = Module['getValue'];
        this.m.setValue = Module['setValue'];
        this.m.buffer   = Module['HEAPU8']['buffer'];

        var max_size_needed = 0;
        this.func_arg_pos_in_buffer = {};
        for (var fname in this.function_arguments)
        {
            if (this.function_arguments.hasOwnProperty(fname))
            {
                var num_args = this.function_arguments[fname].length;
                this.func_arg_pos_in_buffer[fname] = [];
                var p =  this.func_arg_pos_in_buffer[fname];
                var size_needed = this.function_arguments[fname].reduce(function(acc, x) { 
                    if (x != 0)
                    {
                        p.push(acc);
                    }
                    return acc +  Math.ceil(Math.abs(x)/4)*4;
                }, 0);
                if (size_needed > max_size_needed)
                {
                    max_size_needed = size_needed;
                }
                var args = Array.apply(null, new Array(num_args)).map(function(){return 'number'});
                this.wrappers[fname] = this.m.cwrap(fname, 'number', args);
            }
        }

        this.buffer_ptr = this.m.malloc(max_size_needed);
        var context_create = this.m.cwrap('secp256k1_context_create', 'number', ['number']);
        this.context = context_create(1 << 0 | 1 << 1 | 1 << 7 | 1 << 8);
    },
    destroy: function() {
        if (this.buffer_ptr != null)
        {
            this.m.free(this.buffer_ptr);
        }
        var context_destroy = this.m.cwrap('secp256k1_context_destroy', 'number', ['number']);
        context_destroy(this.context);
        this.context = null;
        this.func_arg_pos_in_buffer = {};
        this.wrappers = {};
    },
    m: {}, // Holds aliases to important Module functions (workaround to Closure issues)
    wrappers: {}, // contains wrappers to exported functions
    context: null, // secp256k1 context
    buffer_ptr: null, // Pointer to data on heap reserved for input and/or outpute arguments that must be passed as pointers
    func_arg_pos_in_buffer: {},
    call_wrapper: function(fname) {
        var func_arg_sizes = this.function_arguments[fname];
        var func_args = [];
        if (arguments.length <= func_arg_sizes.length)
        {
            throw "Not all arguments were provided.";
        }
        for (var i = 0, j = 0; i < func_arg_sizes.length; ++i)
        {
            var val = arguments[i+1];
            if (func_arg_sizes[i] == 0)
            {
                func_args.push((val == null) ? 0 : val);
            }
            else
            {
                var ptr = this.buffer_ptr + this.func_arg_pos_in_buffer[fname][j];
                func_args.push(ptr);
                if (val instanceof Uint8Array)
                {
                    //  Copy Uint8Array argument that was passed in into the appropriate region in the buffer
                    var region = new Uint8Array(this.m.buffer, ptr, Math.abs(func_arg_sizes[i]));
                    region.set(val);
                }
                else if (val != null && val.hasOwnProperty('num') && val.hasOwnProperty('type')) // A number passed by reference with additional type data
                {
                    // Store the number in the num field of the argument that was passed in into the appropriate spot in the buffer.
                    // Uses the type of the number from type field to properly store the number in the buffer.
                    this.m.setValue(ptr, val['num'], val['type']);
                }
                ++j;
            }
        }
        
        var ret = this.wrappers[fname].apply(this, func_args);
        
        for (var i = 0, j = 0; i < func_arg_sizes.length; ++i)
        {
            var val = arguments[i+1];
            if (func_arg_sizes[i] < 0)
            {
                var ptr = this.buffer_ptr + this.func_arg_pos_in_buffer[fname][j];
                if (val instanceof Uint8Array)
                {
                    // Extract potentially modified char array from buffer and copy into the Uint8Array argument that was passed in.
                    var region = new Uint8Array(this.m.buffer, ptr, Math.abs(func_arg_sizes[i]));
                    val.set(region);
                }
                else if (val != null && val.hasOwnProperty('num') && val.hasOwnProperty('type'))
                {
                    // Extract number from buffer and store in the num field of the argument that was passed in.
                    // Uses the type of the number from type field to properly extract the number from the buffer.
                    val['num'] = this.m.getValue(ptr, val['type']);
                }
            }
            if (func_arg_sizes[i] != 0)
            {
                ++j;
            }
        }
        
        return ret;
    },    


    api: {
    'ecdsa_recover': function(msg, sig, recid) {
        var pubkeylen = {'num': 0, 'type': 'i32'};
        var pubkey = new Uint8Array(33);
        var ret = this.call_wrapper('secp256k1_ecdsa_recover_compact', this.context, msg, sig, pubkey, pubkeylen, 1, recid);
        switch(ret) {
            case 1:
                if (pubkeylen['num'] != 33)
                {
                    throw "Length of computer compressed pubkey is " + pubkeylen['num'] + " rather than 33.";
                }
                return pubkey;
            case 0:
                throw  "Unable to recover public key";
            default:
                throw "Unknown return value: " + ret;
        }
    },
    'ecdsa_sign': function(msg, seckey) {
        var recid = {'num': 0, 'type': 'i32'};
        var sig = new Uint8Array(64);
        var ret = this.call_wrapper('secp256k1_ecdsa_sign_compact', this.context, msg, sig, seckey, null, null, recid);
        switch(ret) {
            case 1:
                return {'sig': sig, 'recid': recid['num']};
            case 0:
                throw "Unable to sign";
            default:
                throw "Unknown return value: " + ret;
        }
    },
    'point': function(seckey) {
        var pubkeylen = {'num': 33, 'type': 'i32'};
        var pubkey = new Uint8Array(33);
        var ret = this.call_wrapper('secp256k1_ec_pubkey_create', this.context, pubkey, pubkeylen, seckey, 1);
        switch(ret) {
            case 1:
                if (pubkeylen['num'] != 33)
                {
                    throw "Length of computed compressed pubkey is " + pubkeylen['num'] + " rather than 33.";
                }
                return pubkey
            case 0:
                throw "Secret key is invalid";
            default:
                throw "Unknown return value: " + ret;
        }
    },
    'verify_seckey': function(seckey) {
        var ret = this.call_wrapper('secp256k1_ec_seckey_verify', this.context, seckey);
        switch(ret) {
            case 1:
                return true;
            case 0:
                return false;
            default:
                throw "Unknown return value: " + ret;
        }
    },
    'scalar_set': function(scalar, bin) {
        var overflow = {'num': 0, 'type': 'i32'};
        this.call_wrapper('secp256k1_scalar_set_b32', scalar, bin, overflow);
        return {'scalar': scalar, 'overflow': (overflow['num'] == 0) ? false : true};
    },

    }
};

Module = {};
Module['noInitialRun']  = true;
Module['noExitRuntime'] = true;
Module['onRuntimeInitialized'] = function() {
    libsecp256k1.init();
    postMessage({'type': 'init_complete'});
};

onmessage = function(event) {
    if (event.data instanceof ArrayBuffer)
    {
        // Assuming this is the first message by init that was just to test Transferable Object support.
        // Return function names in API
        var function_names = [];
        for (var fname in libsecp256k1.api)
        {
            if (libsecp256k1.api.hasOwnProperty(fname))
            {
                function_names.push(fname);
            }
        }
        postMessage({'type': 'function_names', 'result': function_names});
        return; 
    }
    var data = event.data;
    if (data['operation'] == undefined)
    {
        return;
    }
    var ret = null;
    try {
        if (data['operation'] == 'destroy')
        {
            libsecp256k1.destroy();
            ret = {'type': 'destroy_complete'};
        }
        else if (libsecp256k1.api.hasOwnProperty(data['operation']))
        {
            var args = []; // Unfortunately postMessage doesn't preserve the proper Array structure for some reason.
            for (var i = 0; i < data['args_length']; ++i)
            {
                args.push(data['args'][i]);
            }

            ret = libsecp256k1.api[data['operation']].apply(libsecp256k1, args);
        }  
    } catch (err) {
        if (err['message'] == undefined)
        {
            postMessage({'error': err});
        }
        else
        {
            postMessage({'error': err['message']}); // Need this for some reason. Otherwise I sometimes get DataCloneError. 
        }
        return;
    }
    if (ret == null)
    {
        postMessage({'error': "Unrecognized operation: " + data['operation']});
    }
    else
    {
        postMessage(ret);
    }
}

} else {
// Not in Web Worker
throw 'This script needs to run in a Web Worker.';
}


