<template>
  <div class="sessions">
    <h3 class="session-title">Port Forward Sessions</h3>
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Cluster</th>
          <th>Host/Namespace</th>
          <th>External Port/Service</th>
          <th>Local Port</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(session, index) in sessions" :key="index">
          <td>{{ session.type }}</td>
          <td>{{ session.cluster }}</td>
          <td>{{ session.host || session.namespace }}</td>
          <td>{{ session.externalPort || session.service }}</td>
          <td>{{ session.localPort }}</td>
          <td><button @click="stopSession(index)" class="btn-secondary">Stop</button></td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
const props = defineProps(['sessions']);
const emit = defineEmits(['stop-session']);

const stopSession = (index) => {
  emit('stop-session', index);
};
</script>

<style scoped>
.sessions {
  margin-top: 1.5rem;
}

.session-title {
  font-size: 1.25rem;
  font-weight: bold;
  margin-bottom: 1rem;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 0.75rem;
  border: 1px solid #ccc;
  text-align: left;
}

th {
  background-color: #4a5568;
  color: var(--color-light);
}

td {
  background-color: #2d3748;
  color: var(--color-light);
}

.btn-secondary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  color: var(--color-dark);
  background-color: var(--color-secondary);
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-secondary:hover {
  background-color: #e67e22;
  transform: translateY(-2px);
}
</style>
