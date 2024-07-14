<template>
  <div class="service-setup">
    <h4 class="text-lg font-semibold mb-4">External Service Setup for {{ cluster.name }}</h4>
    <!-- Your external service setup code goes here -->
  </div>
</template>

<script setup>
import { defineProps } from 'vue';

const props = defineProps({
  cluster: Object
});
</script>

<style scoped>
.service-setup {
  background: var(--color-dark);
  padding: 1rem;
  border-radius: 0.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  color: var(--color-light);
}
</style>
