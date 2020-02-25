const sse = new EventSource('/events?stream=requests');
sse.addEventListener('message', e => console.log(JSON.parse(e.data)));

const vm = new Vue({
  el: '#app',
});
