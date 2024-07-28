<template>
  <div>
    <p class="instruction">Select a cluster to continue:</p>
    <ul class="cluster-list">
      <li v-for="cluster in clusters" :key="cluster.name">
        <button @click="selectCluster(cluster)" class="btn-cluster">
          {{ cluster.name }} - {{ cluster.server }}
        </button>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { defineProps, defineEmits } from 'vue';

const props = defineProps({
  clusters: {
    type: Array,
    required: true,
  },
});

const emit = defineEmits(['selected']);

const selectCluster = (cluster) => {
  emit('selected', cluster);
};
</script>

<style scoped>
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
  color: var(--color-light);
  background-color: #4a5568;
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-cluster:hover {
  background-color: #2d3748;
  transform: translateY(-2px);
}
</style>
