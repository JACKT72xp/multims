import { ref, onMounted, emit } from 'vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const clusters = ref([]);
const fetchClusters = async () => {
    try {
        const response = await fetch('/api/clusters');
        const data = await response.json();
        clusters.value = data.clusters;
    }
    catch (error) {
        console.error('Error fetching clusters:', error);
    }
};
const selectCluster = (cluster) => {
    // Set the selected cluster in a store or a state management solution
    console.log('Selected cluster:', cluster);
    emit('selected');
};
onMounted(() => {
    fetchClusters();
});
const __VLS_fnComponent = (await import('vue')).defineComponent({});
let __VLS_functionalComponentProps;
function __VLS_template() {
    let __VLS_ctx;
    /* Components */
    let __VLS_otherComponents;
    let __VLS_own;
    let __VLS_localComponents;
    let __VLS_components;
    let __VLS_styleScopedClasses;
    // CSS variable injection 
    // CSS variable injection end 
    let __VLS_resolvedLocalAndGlobalComponents;
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("select-cluster") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({});
    __VLS_elementAsFunction(__VLS_intrinsicElements.ul, __VLS_intrinsicElements.ul)({});
    for (const [cluster] of __VLS_getVForSourceType((__VLS_ctx.clusters))) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.li, __VLS_intrinsicElements.li)({ ...{ onClick: (...[$event]) => {
                    __VLS_ctx.selectCluster(cluster);
                    // @ts-ignore
                    [clusters, selectCluster,];
                } }, key: ((cluster.name)), });
        (cluster.name);
    }
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['select-cluster'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                clusters: clusters,
                selectCluster: selectCluster,
            };
        },
    });
}
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
;
