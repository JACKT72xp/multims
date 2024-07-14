<template>
  <div class="service-setup">
    <h4 class="text-lg font-semibold mb-4">Internal Service Setup for {{ cluster.name }}</h4>
    <div v-if="error" class="alert alert-error">
      {{ error }}
    </div>
    <div v-if="loadingNamespaces" class="loader">Loading namespaces...</div>
    <div v-else>
      <select v-model="selectedNamespace" @change="fetchServices" class="dropdown">
        <option value="" disabled selected>Select a namespace</option>
        <option v-for="ns in namespaces" :key="ns" :value="ns">{{ ns }}</option>
      </select>
      <div v-if="loadingServices" class="loader">Loading services...</div>
      <div v-else>
        <ul class="service-list">
          <li v-for="service in services" :key="service.name" class="service-item">
            <button @click="selectService(service)" class="btn-service">
              {{ service.name }} - Port: {{ service.port }}
            </button>
          </li>
        </ul>
      </div>
    </div>
    <div v-if="selectedService" class="service-details">
      <h5 class="text-md font-semibold mb-2">Service Details</h5>
      <textarea class="textarea-details" readonly>{{ serviceDetails }}</textarea>
      <input v-model="customPort" placeholder="Custom Port" type="number" class="input-port" />
      <div v-if="portForwarding" class="port-forwarding-status">
        <p>Port forwarding active on localhost:{{ customPort }}</p>
        <button @click="stopPortForward" class="btn-secondary">STOP</button>
      </div>
      <button v-if="!portForwarding" @click="startPortForward" class="btn-primary">FORWARD</button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';

const props = defineProps({
  cluster: Object
});

const error = ref('');
const namespaces = ref([]);
const selectedNamespace = ref('');
const services = ref([]);
const selectedService = ref(null);
const serviceDetails = ref('');
const customPort = ref('');
const loadingNamespaces = ref(false);
const loadingServices = ref(false);
const portForwarding = ref(false);

const fetchNamespaces = async () => {
  loadingNamespaces.value = true;
  try {
    const response = await axios.get('/api/namespaces');
    console.log('Namespaces:', response.data.namespaces);  // Debugging line
    namespaces.value = response.data.namespaces;
  } catch (err) {
    error.value = 'Failed to load namespaces: ' + err.message;
  } finally {
    loadingNamespaces.value = false;
  }
};

const fetchServices = async () => {
  if (!selectedNamespace.value) return;
  loadingServices.value = true;
  try {
    const response = await axios.get(`/api/services?namespace=${selectedNamespace.value}`);
    services.value = response.data.services;
  } catch (err) {
    error.value = 'Failed to load services: ' + err.message;
  } finally {
    loadingServices.value = false;
  }
};

const selectService = (service) => {
  selectedService.value = service;
  serviceDetails.value = `Name: ${service.name}\nPort: ${service.port}\nLabels: ${JSON.stringify(service.labels, null, 2)}`;
};

const startPortForward = async () => {
  if (!customPort.value || !selectedService.value) {
    error.value = 'Please select a service and enter a custom port.';
    return;
  }

  try {
    const response = await axios.post('/api/start-port-forward', {
      namespace: selectedNamespace.value,
      service: selectedService.value.name,
      localPort: customPort.value,
      cluster: {
        name: props.cluster.name,
        user: props.cluster.user
      }
    });

    if (response.status === 200) {
      portForwarding.value = true;
      alert(`Service ${selectedService.value.name} forwarded to localhost:${customPort.value}`);
    }
  } catch (err) {
    error.value = `Failed to start port forward: ${err.response.data}`;
    console.error('Port forward error:', err.response.data);
  }
};


const stopPortForward = async () => {
  if (!customPort.value || !selectedService.value) {
    error.value = 'Please select a service and enter a custom port.';
    return;
  }

  try {
    await axios.post('/api/stop-port-forward', {
      namespace: selectedNamespace.value,
      service: selectedService.value.name,
      localPort: customPort.value,
    });
    portForwarding.value = false;
    alert(`Port forwarding for service ${selectedService.value.name} on localhost:${customPort.value} stopped.`);
  } catch (err) {
    error.value = 'Failed to stop port forward: ' + err.message;
  }
};

onMounted(fetchNamespaces);
</script>

<style scoped>
.service-setup {
  background: var(--color-dark);
  padding: 1rem;
  border-radius: 0.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  color: var(--color-light);
}
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
.loader {
  color: var(--color-light);
  text-align: center;
  padding: 1rem;
}
.dropdown {
  width: 100%;
  padding: 0.75rem;
  margin-bottom: 1rem;
  border-radius: 0.5rem;
  border: 1px solid #ccc;
  background: #2d3748;
  color: var(--color-light);
  font-size: 1rem;
}
.service-list {
  list-style-type: none;
  padding: 0;
  margin: 0;
}
.service-item {
  margin-bottom: 0.5rem;
}
.btn-service {
  display: block;
  width: 100%;
  padding: 0.75rem;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: left;
  text-decoration: none;
  color: var(--color-light);
  background-color: #4a5568;
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}
.btn-service:hover {
  background-color: #2d3748;
  transform: translateY(-2px);
}
.service-details {
  margin-top: 1rem;
}
.textarea-details {
  width: 100%;
  height: 100px;
  padding: 0.75rem;
  border-radius: 0.5rem;
  border: 1px solid #ccc;
  background: #2d3748;
  color: var(--color-light);
  font-size: 1rem;
  margin-bottom: 1rem;
}
.input-port {
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
.btn-primary:hover {
  background-color: #0056b3;
  transform: translateY(-2px);
}
.btn-secondary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem 0;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  color: var(--color-light);
  background-color: var(--color-secondary);
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}
.btn-secondary:hover {
  background-color: #e06c00;
  transform: translateY(-2px);
}
.port-forwarding-status {
  margin-top: 1rem;
  padding: 1rem;
  background-color: #2d3748;
  border-radius: 0.5rem;
  text-align: center;
}
</style>
