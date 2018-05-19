
var assert = chai.assert;

var ws_uri = 'ws://127.0.0.1:9765/test';

describe('signaling-server', function() {
	it('can connect two peers', function(done) {
	  var ws1 = new WebSocket(ws_uri);
	  ws1.onerror = (e)=>{console.error('ws1 error',e);}
	  ws1.onclose = (e)=>{console.log('ws1 closed',e);}
	  var ws2 = new WebSocket(ws_uri);
	  ws2.onerror = (e)=>{console.error('ws2 error',e);}
	  ws2.onclose = (e)=>{console.log('ws2 closed',e);}
	  
	  
	  const promises = [
	  	new Promise(resolve => {
	  		ws1.onmessage= (e)=>{ console.log('ws1 msg:',e.data);
	  			assert.equal('0', e.data);
	  			ws1.onmessage= (e)=>{ console.log('ws1 msg:',e.data);
	  				assert.equal('ws2: hi', e.data);
	      			resolve();
	      		};
	      		ws1.send('ws1: hi');
	      	};
		}),
		new Promise(resolve => {
		  	ws2.onmessage= (e)=>{ console.log('ws2 msg:',e.data);
		  		assert.equal('1', e.data);
		  		ws2.onmessage= (e)=>{ console.log('ws2 msg:',e.data);
		  			assert.equal('ws1: hi', e.data);
	      			resolve();
	      		};
	      		ws2.send('ws2: hi');
	      	};
		})
	  ];
	  Promise.all(promises).then(e=>{}).then(done);
	  
	});
});