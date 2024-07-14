<template>
  <div>
    <div :class="['fixed top-0 left-0 h-full z-50 transition-transform duration-300', isOpen ? 'translate-x-0' : '-translate-x-full']">
      <nav class="bg-dark p-6 w-64 shadow-lg">
        <div class="flex items-center justify-between mb-6">
          <div class="text-white font-bold text-2xl">Multims</div>
          <button @click="toggleMenu" class="text-white">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-6 h-6">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div>
          <RouterLink to="/" class="nav-link block text-light mb-4 hover:text-primary" @click="toggleMenu">Home</RouterLink>
          <RouterLink to="/console" class="nav-link block text-light mb-4 hover:text-primary" @click="toggleMenu">Console</RouterLink>
          <RouterLink to="/port-forward" class="nav-link block text-light mb-4 hover:text-primary" @click="toggleMenu">Port Forward</RouterLink>
          <RouterLink to="/about" class="nav-link block text-light hover:text-primary" @click="toggleMenu">About</RouterLink>
        </div>
      </nav>
    </div>
    <button class="fixed top-6 left-6 z-50 p-2 bg-primary text-white rounded-full shadow-lg hover:bg-opacity-80" @click="toggleMenu" style="transform: translateY(10px);">
      <svg v-if="!isOpen" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" class="w-6 h-6">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7" />
      </svg>
    </button>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { RouterLink } from 'vue-router';

const isOpen = ref(false);

const toggleMenu = () => {
  isOpen.value = !isOpen.value;
};
</script>

<style scoped>
.nav-link {
  transition: all 0.3s ease-in-out;
}
</style>
