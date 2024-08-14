<template>
  <div>
    <h4 class="text-lg font-semibold mb-4">External Service Setup</h4>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div>
      <input v-model="host" placeholder="Host" class="input-field mb-4" />
      <input v-model="externalPort" placeholder="External Port" type="number" class="input-field mb-4" />
      <button @click="validateService" :disabled="loading" class="btn-primary mb-4">{{ loading ? "Validating..." : "Validate" }}</button>
      <div v-if="validated">
        <input v-model="localPort" placeholder="Local Port" type="number" class="input-field mb-4" />
        <button @click="startPortForward" :disabled="loading" class="btn-primary">{{ loading ? "Forwarding..." : "Forward" }}</button>
      </div>
      <button @click="cancel" class="btn-secondary">Cancel</button>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import axios from 'axios';

const props = defineProps({
  context: {
    type: Object,
    required: true,
    validator(value) {
      return value && value.name && value.cluster;
    },
  },
});

const emit = defineEmits(['forward', 'cancel']);

const error = ref('');
const host = ref('');
const externalPort = ref('');
const localPort = ref('');
const validated = ref(false);
const loading = ref(false);

const validateService = async () => {
  error.value = '';
  loading.value = true;
  try {
    await axios.post('/api/validate-external-service', {
      host: host.value,
      port: externalPort.value,
      context: props.context.name, // Pasar el nombre del contexto
      clusterName: props.context.cluster // Pasar también el nombre del clúster
    });
    validated.value = true;
  } catch (err) {
    error.value = 'Failed to validate external service: ' + err.message;
  } finally {
    loading.value = false;
  }
};

const startPortForward = async () => {
  error.value = '';
  loading.value = true;
  try {
    const response = await axios.post('/api/start-external-port-forward', {
      host: host.value,
      port: externalPort.value,
      localPort: localPort.value,
      context: props.context.name, // Pasar el nombre del contexto
      clusterName: props.context.cluster // Pasar también el nombre del clúster
    });
    const session = {
      id: response.data.id,
      type: 'External',
      cluster: props.context.cluster,
      hostNamespace: host.value,
      externalPortService: externalPort.value,
      localPort: localPort.value
    };
    emit('forward', session);
  } catch (err) {
    error.value = 'Failed to start port forward: ' + err.message;
  } finally {
    loading.value = false;
  }
};

const cancel = () => {
  emit('cancel');
};
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