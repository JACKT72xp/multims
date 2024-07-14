<template>
  <nav :class="['sidebar', { active: isActive }]">
    <ul>
      <li><router-link to="/">Home</router-link></li>
      <li><router-link to="/console">Console</router-link></li>
      <li><router-link to="/port-forward">Port Forward</router-link></li>
      <li><router-link to="/settings">Settings</router-link></li>
      <li><router-link to="/about">About</router-link></li>
      <li><a href="index.html">Close Console</a></li>
    </ul>
  </nav>
</template>

<script setup>
import { ref } from 'vue'

const isActive = ref(false)

const toggleMenu = () => {
  isActive.value = !isActive.value
}
</script>

<style scoped>
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  width: 200px;
  height: 100%;
  background-color: #333;
  color: #fff;
  transform: translateX(-100%);
  transition: transform 0.3s ease;
}

.sidebar.active {
  transform: translateX(0);
}

.sidebar ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.sidebar ul li {
  padding: 1rem;
}

.sidebar ul li a {
  color: #fff;
  text-decoration: none;
}

.sidebar ul li a:hover {
  text-decoration: underline;
}
</style>
