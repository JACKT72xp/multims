<template>
  <div class="new-session-form">
    <h3 class="session-title">New Forward Session</h3>
    <form @submit.prevent="submitForm">
      <div class="form-group">
        <label for="type">Type</label>
        <select v-model="session.type" id="type" required>
          <option value="Internal">Internal</option>
          <option value="External">External</option>
        </select>
      </div>

      <div v-if="session.type === 'Internal'">
        <div class="form-group">
          <label for="namespace">Namespace</label>
          <select v-model="session.namespace" id="namespace" required @change="loadServices">
            <option v-for="ns in namespaces" :key="ns" :value="ns">{{ ns }}</option>
          </select>
        </div>

        <div class="form-group">
          <label for="service">Service</label>
          <select v-model="session.service" id="service" required>
            <option v-for="svc in services" :key="svc.name" :value="svc.name">{{ svc.name }} ({{ svc.port }})</option>
          </select>
        </div>
      </div>

      <div v-if="session.type === 'External'">
        <div class="form-group">
          <label for="host">Host</label>
          <input v-model="session.host" id="host" type="text" required />
        </div>

        <div class="form-group">
          <label for="externalPort">External Port</label>
          <input v-model="session.externalPort" id="externalPort" type="number" required />
        </div>

        <button type="button" @click="validateExternalService" class="btn-primary">Validate</button>
      </div>

      <div v-if="session.type === 'Internal' || validated">
        <div class="form-group">
          <label for="localPort">Local Port</label>
          <input v-model="session.localPort" id="localPort" type="number" required />
        </div>
      </div>

      <div class="form-group">
        <button type="submit" class="btn-primary">Forward</button>
        <button type="button" @click="$emit('cancel')" class="btn-secondary">Cancel</button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue';
import axios from 'axios';

const props = defineProps({
  cluster: Object,
});

const session = ref({
  type: 'Internal',
  namespace: '',
  service: '',
  host: '',
  externalPort: '',
  localPort: '',
});

const namespaces = ref([]);
const services = ref([]);
const validated = ref(false);
const error = ref('');

const loadNamespaces = async () => {
  try {
    const response = await axios.get(`/api/namespaces?cluster=${props.cluster.name}`);
    namespaces.value = response.data.namespaces;
  } catch (err) {
    error.value = 'Failed to load namespaces';
    console.error('Load namespaces error:', err);
  }
};

const loadServices = async () => {
  if (!session.value.namespace) return;
  try {
    const response = await axios.get(`/api/services?cluster=${props.cluster.name}&namespace=${session.value.namespace}`);
    services.value = response.data.services;
  } catch (err) {
    error.value = 'Failed to load services';
    console.error('Load services error:', err);
  }
};

const validateExternalService = async () => {
  try {
    const response = await axios.post('/api/validate-external-service', {
      host: session.value.host,
      port: session.value.externalPort,
      cluster: props.cluster.name,
    });

    if (response.data.success) {
      validated.value = true;
    } else {
      error.value = 'Validation failed';
    }
  } catch (err) {
    error.value = 'Failed to validate external service';
    console.error('Validation error:', err);
  }
};

const submitForm = async () => {
  if (!session.value.localPort) {
    error.value = 'Please enter a local port';
    return;
  }

  try {
    const response = await axios.post('/api/start-port-forward', {
      type: session.value.type,
      namespace: session.value.namespace,
      service: session.value.service,
      host: session.value.host,
      externalPort: session.value.externalPort,
      localPort: session.value.localPort,
      cluster: props.cluster.name,
    });

    if (response.status === 200) {
      const newSession = response.data;
      $emit('sessionCreated', newSession);
    }
  } catch (err) {
    error.value = 'Failed to start port forward';
    console.error('Port forward error:', err);
  }
};

onMounted(loadNamespaces);

watch(
  () => session.value.type,
  () => {
    if (session.value.type === 'External') {
      validated.value = false;
    }
  }
);
</script>

<style scoped>
.new-session-form {
  text-align: left;
  max-width: 600px;
  margin: 0 auto;
}

.session-title {
  font-size: 1.5rem;
  font-weight: bold;
  margin-bottom: 1rem;
}

.form-group {
  margin-bottom: 1rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: bold;
}

input,
select {
  width: 100%;
  padding: 0.5rem;
  font-size: 1rem;
  border-radius: 0.25rem;
  border: 1px solid #ccc;
  background: #2d3748;
  color: var(--color-light);
}

.btn-primary,
.btn-secondary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem 0;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-primary {
  color: var(--color-light);
  background-color: var(--color-primary);
}

.btn-primary:hover {
  background-color: #0056b3;
  transform: translateY(-2px);
}

.btn-secondary {
  color: var(--color-dark);
  background-color: var(--color-secondary);
}

.btn-secondary:hover {
  background-color: #e67e22;
  transform: translateY(-2px);
}
</style>
