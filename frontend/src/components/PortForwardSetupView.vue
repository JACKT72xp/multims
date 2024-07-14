<template>
  <div>
    <div v-if="error" class="alert alert-error">{{ error }}</div>
    <div v-if="!configLoaded">
      <div class="alert alert-warning">No multims.yaml found. Loading default kubeconfig...</div>
      <input type="file" @change="loadKubeConfigFromFile" class="btn" />
      <button @click="loadKubeConfigDefault" class="btn">Use Default Kubeconfig</button>
    </div>
    <div v-else>
    <p v-if="clusters.length === 0" class="alert alert-warning">No clusters found in the kubeconfig.</p>
    <template v-else>
        <p>Select a cluster to continue:</p>
        <ul>
            <li v-for="cluster in clusters" :key="cluster.name">
                <button @click="selectCluster(cluster)" class="btn">
                    {{ cluster.name }} - {{ cluster.server }}
                </button>
            </li>
        </ul>
    </template>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import yaml from 'js-yaml';
import axios from 'axios';
import InternalServiceSetup from './InternalServiceSetup.vue';
import ExternalServiceSetup from './ExternalServiceSetup.vue';

const error = ref('');
const clusters = ref([]);
const selectedCluster = ref(null);
const configLoaded = ref(false);
const showInternal = ref(false);
const showExternal = ref(false);

const loadKubeConfig = async (event) => {
  try {
    const file = event.target.files[0];
    const text = await file.text();
    const config = yaml.load(text);
    if (config && config.clusters && Array.isArray(config.clusters)) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.cluster?.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error('Invalid kubeconfig structure');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Kubeconfig loading error:', err);
    console.log('Parsed config:', config);  // Add this line for debugging
  }
};

const loadDefaultKubeConfig = async () => {
  try {
    const response = await fetch('/api/load-kube-config');
    const data = await response.json();
    if (response.ok && data.clusters) {
      clusters.value = Object.entries(data.clusters).map(([name, clusterInfo]) => ({
        name,
        server: clusterInfo?.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error(data.message || 'Invalid kubeconfig structure');
    }
  } catch (err) {
    error.value = 'Failed to load default kubeconfig: ' + err.message;
    console.error('Default kubeconfig loading error:', err);
    console.log('Received data:', data);  // Add this line for debugging
  }
};

const loadKubeConfigDefault = async () => {
  try {
    const response = await axios.get('/api/load-kube-config');
    const config = response.data;
    clusters.value = Object.keys(config.clusters).map(name => ({
      name,
      server: config.clusters[name].server
    }));
    configLoaded.value = true;
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
  }
};

const selectCluster = (cluster) => {
  selectedCluster.value = cluster;
  showInternal.value = false;
  showExternal.value = false;
};

const selectInternal = () => {
  showInternal.value = true;
  showExternal.value = false;
};

const selectExternal = () => {
  showInternal.value = false;
  showExternal.value = true;
};
</script>

<style scoped>
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
