Vue.component('RequestInfo', {
  template: `
    <li>
      <code>@{{ info.time }}</code>
      <span :class="badgeClasses(info)">{{ info.type }}</span>
      {{ info.method }} {{ info.url }} {{ info.status }} {{ info.duration }}ms
    </li>
  `,
  props: ['info'],
  methods: {
    badgeClass: function(r) {
      switch (r.type) {
        case 'cache hit':
          return 'badge-warning';
        case 'stored':
          return 'badge-success';
        case 'proxied':
          return 'badge-dark';
        case 'failed':
          return 'badge-danger';
        default:
          return 'badge-info';
      }
    },
    badgeClasses: function(r) {
      let classes = {
        'badge': true,
      };
      classes[this.badgeClass(r)] = true;
      return classes;
    }
  }
});
Vue.component('RequestList', {
  template: `
  <ul>
    <request-info v-for="r in requests.slice().reverse()" :info="r" :key="r.id"/>
  </ul>
  `,
  data: function() {
    return {
      requests: []
    };
  },
  created: function() {
    this.sse = new EventSource('/events?stream=requests');
    this.sse.addEventListener('message', e => {
      let info = JSON.parse(e.data);
      info.id = e.data.lastEventId;
      this.requests.push(info);
    });
  },
  destroyed: function() {
    this.sse.close();
  }
});

const vm = new Vue({
  el: '#app',
});
