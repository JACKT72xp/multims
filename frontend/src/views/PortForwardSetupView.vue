<template>
  <div class="port-forward-setup">
    <div class="card">
      <h2 class="title">Port Forward Setup</h2>
      <div v-if="error" class="alert alert-error">
        {{ error }}
      </div>
      <div v-if="!configLoaded" class="config-loader">
        <div class="alert alert-warning mb-4">
          No multims.yaml found. Loading default kubeconfig...
        </div>
        <input type="file" @change="loadKubeConfigFromFile" class="btn-primary mb-4" />
        <button @click="loadKubeConfigDefault" class="btn-primary">Use Default Kubeconfig</button>
      </div>
      <div v-else>
        <p class="instruction">Select a context to continue:</p>
        <ul class="context-list">
          <li v-for="context in contexts" :key="context.name">
            <button 
              @click="selectContext(context)" 
              :class="['btn-context', { selected: selectedContext && selectedContext.name === context.name }]"
            >
              {{ context.name }} - {{ context.cluster }}
            </button>
          </li>
        </ul>
        <div v-if="selectedContext">
          <h3 class="context-title">{{ selectedContext.name }}</h3>
          <button @click="showInternalForm" class="btn-secondary">Forward Internal Service</button>
          <button @click="showExternalForm" class="btn-secondary">Forward External Service</button>
          <InternalServiceSetup v-if="showInternal" :context="selectedContext" @forward="addSession" />
          <ExternalServiceSetup v-if="showExternal" :context="selectedContext" @forward="addSession" />
        </div>
        <div v-if="sessions.length" class="session-table">
          <h3>Port Forward Sessions</h3>
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
              <tr v-for="session in sessions" :key="session.id">
                <td>{{ session.type }}</td>
                <td>{{ session.cluster }}</td>
                <td>{{ session.hostNamespace }}</td>
                <td>{{ session.externalPortService }}</td>
                <td>{{ session.localPort }}</td>
                <td>
                  <button v-if="session.status === 'running'" @click="stopSession(session)" class="btn-stop">Stop</button>
                  <button v-if="session.status === 'stopped' || session.status === 'registered'" @click="startSession(session)" class="btn-start">Start</button>
                  <button @click="deleteSession(session)" class="btn-delete">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue';
import axios from 'axios';
import InternalServiceSetup from '../components/InternalServiceSetup.vue';
import ExternalServiceSetup from '../components/ExternalServiceSetup.vue';

const error = ref('');
const contexts = ref([]);
const selectedContext = ref(null);
const configLoaded = ref(false);
const showInternal = ref(false);
const showExternal = ref(false);
const sessions = ref(JSON.parse(localStorage.getItem('portForwardSessions') || '[]'));

watch(sessions, (newSessions) => {
  localStorage.setItem('portForwardSessions', JSON.stringify(newSessions));
}, { deep: true });

const loadKubeConfigFromFile = async (event) => {
  try {
    const file = event.target.files[0];
    const formData = new FormData();
    formData.append('kubeconfig', file);

    const response = await axios.post('/api/load-kube-config', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });

    contexts.value = response.data.contexts;
    configLoaded.value = true;
    selectedContext.value = null;
    showInternal.value = false;
    showExternal.value = false;
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Kubeconfig loading error:', err);
  }
};

const loadKubeConfigDefault = async () => {
  try {
    const response = await axios.get('/api/load-kube-config-default');
    contexts.value = response.data.contexts;
    configLoaded.value = true;
    selectedContext.value = null;
    showInternal.value = false;
    showExternal.value = false;
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Default kubeconfig loading error:', err);
  }
};

const selectContext = (context) => {
  selectedContext.value = context;
  showInternal.value = false;
  showExternal.value = false;
};

const showInternalForm = () => {
  showInternal.value = true;
  showExternal.value = false;
};

const showExternalForm = () => {
  showInternal.value = false;
  showExternal.value = true;
};

const addSession = (session) => {
  sessions.value.push(session);
  showInternal.value = false;
  showExternal.value = false;
};

const startSession = async (session) => {
  if (!selectedContext.value) {
    error.value = 'No context selected';
    return;
  }

  try {
    await axios.post('/api/start-external-port-forward', {
      host: session.host,
      localPort: session.localPort,
      context: selectedContext.value.name, // Pasar el nombre del contexto seleccionado
      clusterName: selectedContext.value.cluster, // Pasar también el nombre del clúster
    });
    session.status = 'running';
  } catch (err) {
    console.error('Failed to start port forward:', err);
    error.value = 'Failed to start port forward: ' + err.message;
  }
};

const stopSession = async (session) => {
  try {
    await axios.post('/api/stop-external-port-forward', {
      host: session.host,
      localPort: session.localPort,
    });
    session.status = 'stopped';
  } catch (err) {
    console.error('Failed to stop port forward:', err);
    error.value = 'Failed to stop port forward: ' + err.message;
  }
};

const deleteSession = async (session) => {
  try {
    const url = '/api/delete-external-port-forward';
    await axios.post(url, {
      host: session.hostNamespace,
      localPort: session.localPort,
      context: selectedContext.value.name, // Pasar el nombre del contexto seleccionado
    });
    sessions.value = sessions.value.filter(s => s !== session);
  } catch (err) {
    console.error('Failed to delete port forward:', err);
    error.value = 'Failed to delete port forward: ' + err.message;
  }
};
</script>

<style scoped>

.root {
  --color-primary: #3498db;
  --color-secondary: #e67e22;
  --color-dark: #2c3e50;
  --color-light: #ecf0f1;
  --background-gradient: linear-gradient(135deg, #34495e, #2c3e50);
}

body {
  background: var(--background-gradient);
  color: var(--color-light);
  font-family: 'Inter', sans-serif;
}

.port-forward-setup {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
}

.card {
  background: #34495e;
  padding: 2rem;
  border-radius: 1rem;
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
  text-align: center;
max-width: 800px;
width: 100%;
}

.title {
font-size: 2rem;
font-weight: bold;
margin-bottom: 1rem;
}

.alert {
padding: 1rem;
margin-bottom: 1rem;
border: 1px solid transparent;
border-radius: 0.25rem;
}

.alert-warning {
color: #856404;
background-color: #fff3cd;
border-color: #ffeeba;
}

.alert-error {
color: #e74c3c;
background-color: #fddede;
border-color: #e74c3c;
}

.btn-primary {
display: inline-block;
padding: 0.75rem 1.5rem;
margin: 0.5rem 0;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: center;
text-decoration: none;
color: var(–color-light);
background-color: var(–color-primary);
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-primary:hover {
background-color: #2980b9;
transform: translateY(-2px);
}

.btn-cluster.selected {
background-color: #1a202c; /* Color diferente para el botón seleccionado */
transform: translateY(-2px);
}

.btn-secondary {
display: inline-block;
padding: 0.75rem 1.5rem;
margin: 0.5rem 0.5rem 0 0;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: center;
text-decoration: none;
color: var(–color-dark);
background-color: var(–color-secondary);
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-secondary:hover {
background-color: #d35400;
transform: translateY(-2px);
}

.btn-start {
display: inline-block;
padding: 0.5rem 1rem;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: center;
text-decoration: none;
color: var(–color-light);
background-color: #27ae60;
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-start:hover {
background-color: #229954;
transform: translateY(-2px);
}

.btn-stop {
display: inline-block;
padding: 0.5rem 1rem;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: center;
text-decoration: none;
color: var(–color-light);
background-color: var(–color-secondary);
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-stop:hover {
background-color: #d35400;
transform: translateY(-2px);
}

.btn-delete {
display: inline-block;
padding: 0.5rem 1rem;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: center;
text-decoration: none;
color: var(–color-light);
background-color: #e74c3c;
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-delete:hover {
background-color: #c0392b;
transform: translateY(-2px);
}

.instruction {
font-size: 1.25rem;
margin-bottom: 1rem;
}

.cluster-list {
list-style-type: none;
padding: 0;
margin: 0 0 1.5rem 0;
}

.btn-cluster {
display: block;
width: 100%;
padding: 0.75rem 1.5rem;
margin: 0.5rem 0;
font-size: 1rem;
font-weight: bold;
cursor: pointer;
text-align: left;
text-decoration: none;
color: var(–color-light);
background-color: #4a5568;
border: none;
border-radius: 0.5rem;
transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-cluster:hover {
background-color: #2d3748;
transform: translateY(-2px);
}

.cluster-title {
font-size: 1.5rem;
font-weight: bold;
margin: 1.5rem 0;
}

.session-table {
margin-top: 2rem;
max-height: 400px;
overflow-y: auto;
}

.session-table table {
width: 100%;
border-collapse: collapse;
}

.session-table th,
.session-table td {
padding: 0.75rem;
border: 1px solid #444;
text-align: left;
}

.session-table th {
background-color: #333;
}

.session-table td {
background-color: #2d3748;
}

</style>