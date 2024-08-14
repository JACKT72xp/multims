<template>
  <div>
    <h4 class="text-lg font-semibold mb-4">Internal Service Setup</h4>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div>
      <select v-model="namespace" @change="loadServices" class="input-field mb-4">
        <option disabled value="">Select Namespace</option>
        <option v-for="ns in namespaces" :key="ns" :value="ns">{{ ns }}</option>
      </select>
      <select v-model="selectedService" class="input-field mb-4">
        <option disabled value="">Select Service</option>
        <option v-for="svc in services" :key="svc.name" :value="svc">
          {{ svc.name }}:{{ svc.port }}
        </option>
      </select>
      <input v-model="localPort" placeholder="Local Port" type="number" class="input-field mb-4" />
      <button @click="startPortForward" :disabled="loading" class="btn-primary">{{ loading ? "Forwarding..." : "Forward" }}</button>
      <button @click="cancel" class="btn-secondary">Cancel</button>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

const props = defineProps({
  cluster: Object
});

const emit = defineEmits(['forward', 'cancel']);

const error = ref('');
const namespaces = ref([]);
const services = ref([]);
const namespace = ref('');
const selectedService = ref(null);
const localPort = ref('');
const loading = ref(false);

const loadNamespaces = async () => {
  try {
    const response = await axios.get(`/api/namespaces?cluster=${props.cluster.name}`);
    namespaces.value = response.data.namespaces;
  } catch (err) {
    error.value = 'Failed to load namespaces: ' + err.message;
  }
};

const loadServices = async () => {
  try {
    const response = await axios.get(`/api/services?cluster=${props.cluster.name}&namespace=${namespace.value}`);
    services.value = response.data.services.map(svc => ({
      name: svc.name,
      port: svc.port
    }));
  } catch (err) {
    error.value = 'Failed to load services: ' + err.message;
  }
};

watch(error, (newError) => {
  if (newError) {
    setTimeout(() => {
      error.value = '';
    }, 5000); // Desaparece después de 5 segundos
  }
});


const startPortForward = async () => {
  try {
    loading.value = true;
    const requestData = {
      namespace: namespace.value,
      service: selectedService.value.name,
      localPort: parseInt(localPort.value, 10),
      cluster: {
        name: props.cluster.name,
        user: props.cluster.user // Añadir cualquier otro dato necesario del cluster
      }
    };
    console.log("Request Data:", requestData); // Para depuración

    const response = await axios.post('/api/start-port-forward', requestData);
    const session = {
      id: response.data.id,
      type: 'Internal',
      cluster: props.cluster.name,
      hostNamespace: namespace.value,
      externalPortService: `${selectedService.value.name}:${selectedService.value.port}`,
      localPort: localPort.value
    };
    emit('forward', session);
    emit('cancel'); // Resetea los formularios
  } catch (err) {
    error.value = 'Failed to start port forward: ' + err.message;
  } finally {
    loading.value = false;
  }
};


const cancel = () => {
  emit('cancel');
};

loadNamespaces();
</script>

<style scoped>
.alert {
  padding: 1rem;
  margin-bottom: 1rem;
  border: 1px solid transparent;
  border-radius: 0.25rem;
}

.alert-error {
  color: #f44336;
  background-color: #fddede;
  border-color: #f44336;
}

.input-field {
  width: 100%;
  padding: 0.75rem;
  margin-bottom: 1rem;
  border-radius: 0.5rem;
  border: 1px solid #ccc;
  background: #2d3748;
  color: var(--color-light);
  font-size: 1rem;
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
  color: var(--color-light);
  background-color: var(--color-primary);
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-primary:disabled {
  background-color: #0056b3;
  cursor: not-allowed;
}

.session-table {
  margin-top: 2rem;
  max-height: 400px; /* O la altura que prefieras */
  overflow-y: auto;
}

.btn-primary:hover {
  background-color: #0056b3;
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
