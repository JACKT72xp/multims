<template>
  <div class="port-forward-sessions">
    <h3>Port Forward Sessions</h3>
    <button @click="showNewSessionForm = true" class="btn-primary">New Forward Session</button>
    <div class="loader" v-if="loading"></div>
    <table v-if="!loading" class="table-auto">
      <thead>
        <tr>
          <th>Type</th>
          <th>Cluster</th>
          <th>Host</th>
          <th>External Port</th>
          <th>Local Port</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="session in portForwards" :key="session.localPort">
          <td>{{ session.type }}</td>
          <td>{{ session.cluster.name }}</td>
          <td>{{ session.externalHost }}</td>
          <td>{{ session.externalPort }}</td>
          <td>{{ session.localPort }}</td>
          <td>
            <button @click="stopPortForward(session.localPort)" class="btn-secondary">Stop</button>
          </td>
        </tr>
      </tbody>
    </table>
    <NewSessionForm v-if="showNewSessionForm" @close="hideNewSessionForm" @new-session="newSession" />
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';
import NewSessionForm from '../components/NewSessionForm.vue';

const props = defineProps({
  cluster: {
    type: Object,
    required: true,
  },
});

const portForwards = ref([]);
const showNewSessionForm = ref(false);
const loading = ref(false);

const hideNewSessionForm = () => {
  showNewSessionForm.value = false;
};

const newSession = (newSession) => {
  portForwards.value.push({
    ...newSession,
    type: newSession.type,
    cluster: props.cluster,
  });
  hideNewSessionForm();
};

const stopPortForward = async (localPort) => {
  try {
    loading.value = true;
    const forward = portForwards.value.find(f => f.localPort === localPort);
    if (!forward) return;

    const response = await axios.post('/api/stop-external-port-forward', {
      host: forward.externalHost,
      port: forward.externalPort,
      localPort: forward.localPort
    });

    if (response.status === 200) {
      portForwards.value = portForwards.value.filter(f => f.localPort !== localPort);
      alert(`Port forwarding for localhost:${localPort} stopped.`);
    }
  } catch (err) {
    console.error('Stop port forward error:', err.response.data);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped lang="scss">
.port-forward-sessions {
  padding: 2rem;
  background: var(--color-dark);
  color: var(--color-light);
  border-radius: 0.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  max-width: 100%;
  margin: 0 auto;
}

.table-auto {
  width: 100%;
  margin-bottom: 1rem;
  border-collapse: collapse;
  font-size: 1.2rem;
}

.table-auto th,
.table-auto td {
  border: 1px solid #ccc;
  padding: 0.75rem;
  text-align: left;
  color: var(--color-light);
}

.table-auto th {
  background-color: #4a5568;
}

.table-auto tbody tr:nth-child(odd) {
  background-color: #3b4252;
}

.table-auto tbody tr:nth-child(even) {
  background-color: #2d3748;
}

.loader {
  border: 16px solid #f3f3f3;
  border-radius: 50%;
  border-top: 16px solid var(--color-primary);
  width: 120px;
  height: 120px;
  animation: spin 2s linear infinite;
  margin: 0 auto;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}
</style>
