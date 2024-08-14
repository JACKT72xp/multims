<template>
  <div class="port-forward-setup">
    <h2 class="text-xl font-bold mb-4">Port Forward Setup</h2>
    <div v-if="error" class="alert alert-error">
      {{ error }}
    </div>
    <div v-if="!configLoaded">
      <div class="alert alert-warning">
        No multims.yaml found. Loading default kubeconfig...
      </div>
      <input type="file" @change="loadKubeConfigFromFile" class="btn" />
      <button @click="loadKubeConfigDefault" class="btn">Use Default Kubeconfig</button>
    </div>
    <div v-else>
      <p>Select a cluster to continue:</p>
      <ul>
        <li v-for="cluster in clusters" :key="cluster.name">
          <button @click="selectCluster(cluster)" class="btn">
            {{ cluster.name }} - {{ cluster.server }}
          </button>
        </li>
      </ul>
      <div v-if="selectedCluster">
        <h3>{{ selectedCluster.name }}</h3>
        <button @click="selectInternal" class="btn">Forward Internal Service</button>
        <button @click="selectExternal" class="btn">Forward External Service</button>
        <InternalServiceSetup v-if="showInternal" :cluster="selectedCluster" />
        <ExternalServiceSetup v-if="showExternal" :cluster="selectedCluster" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import yaml from 'js-yaml';
import axios from 'axios';
import InternalServiceSetup from '../components/InternalServiceSetup.vue';
import ExternalServiceSetup from '../components/ExternalServiceSetup.vue';

// Define reactive variables
const error = ref('');
const clusters = ref([]);
const selectedCluster = ref(null);
const configLoaded = ref(false);
const showInternal = ref(false);
const showExternal = ref(false);

// Function to load kubeconfig from a file
const loadKubeConfigFromFile = async (event) => {
  try {
    const file = event.target.files[0];
    const text = await file.text();
    const config = yaml.load(text);

    if (config && config.clusters) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.cluster.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error('Invalid kubeconfig format');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Kubeconfig loading error:', err);
  }
};

// Function to load default kubeconfig
const loadKubeConfigDefault = async () => {
  try {
    const response = await axios.get('/api/load-kube-config');
    const config = response.data;

    if (config && config.clusters) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.cluster.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error('Invalid kubeconfig format');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Default kubeconfig loading error:', err);
  }
};

// Function to select a cluster
const selectCluster = (cluster) => {
  selectedCluster.value = cluster;
  showInternal.value = false;
  showExternal.value = false;
};

// Function to show internal service setup
const selectInternal = () => {
  showInternal.value = true;
  showExternal.value = false;
};

// Function to show external service setup
const selectExternal = () => {
  showInternal.value = false;
  showExternal.value = true;
};
</script>

<style scoped>
.port-forward-setup {
  max-width: 600px;
  margin: 0 auto;
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
  color: #f44336;
  background-color: #fddede;
  border-color: #f44336;
}
.btn {
  display: inline-block;
  padding: 0.5rem 1rem;
  margin: 0.5rem;
  font-size: 1rem;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  color: #ffffff;
  background-color: #007bff;
  border: 1px solid transparent;
  border-radius: 0.25rem;
}
.btn:hover {
  background-color: #0056b3;
}
</style>
