<template>
  <div class="h-screen overflow-hidden relative bg-gradient-to-r from-blue-900 to-blue-700 text-white">
    <div class="fixed top-0 left-0 w-full flex items-center p-4 z-10">
      <div class="flex items-center ml-4">
        <div class="relative z-20">
          <button @click="toggleMenu" class="focus:outline-none">
            <img src="@/assets/load-svgrepo-com.svg" alt="Menu" class="w-8 h-8 transition-transform duration-500" :class="{'rotate-180': menuOpen}" />
          </button>
        </div>
        <router-link to="/" class="text-white font-bold text-xl ml-2">Multims</router-link>
      </div>
    </div>
    <transition name="slide-fade">
      <nav v-if="menuOpen" class="fixed top-10 left-10 w-64 bg-black bg-opacity-90 text-white p-4 z-30 rounded-lg shadow-xl">
        <div class="flex justify-between items-center mb-8">
          <router-link to="/" class="text-white font-bold text-2xl">Multims</router-link>
          <button @click="toggleMenu" class="text-white text-2xl focus:outline-none">&times;</button>
        </div>
        <ul>
          <li class="mb-4">
            <router-link to="/" class="nav-link">Home</router-link>
          </li>
          <li class="mb-4">
            <router-link to="/console" class="nav-link">Console</router-link>
          </li>
          <li class="mb-4">
            <router-link to="/port-forward" class="nav-link">Port Forward</router-link>
          </li>
          <li>
            <router-link to="/about" class="nav-link">About</router-link>
          </li>
        </ul>
      </nav>
    </transition>
    <router-view></router-view>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'

const menuOpen = ref(false)

const toggleMenu = () => {
  menuOpen.value = !menuOpen.value
}

onMounted(() => {
  setInterval(() => {
    const menuIcon = document.querySelector('img[alt="Menu"]')
    if (menuIcon) {
      menuIcon.classList.add('rotate-animation')
      setTimeout(() => {
        menuIcon.classList.remove('rotate-animation')
      }, 60000) // 60 seconds
    }
  }, 60000) // 60 seconds
})
</script>

<style>
.slide-fade-enter-active {
  transition: all 0.3s ease;
}
.slide-fade-leave-active {
  transition: all 0.3s ease;
}
.slide-fade-enter-from,
.slide-fade-leave-to {
  transform: translateX(-100%);
  opacity: 0;
}

.nav-link {
  font-size: 1.25rem;
  color: white;
  text-decoration: none;
}

.nav-link:hover {
  color: var(--color-primary);
}

.rotate-animation {
  animation: rotate 60s linear infinite;
}

@keyframes rotate {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

body {
  margin: 0;
  font-family: 'Inter', sans-serif;
}
</style>
