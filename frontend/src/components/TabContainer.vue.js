import { ref } from 'vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const tabs = ref([{ name: 'Console 1' }, { name: 'Console 2' }]);
const activeTab = ref(0);
const setActiveTab = (index) => {
    activeTab.value = index;
};
const addTab = () => {
    tabs.value.push({ name: `Console ${tabs.value.length + 1}` });
    activeTab.value = tabs.value.length - 1;
};
const removeTab = (index) => {
    tabs.value.splice(index, 1);
    if (activeTab.value >= tabs.value.length) {
        activeTab.value = tabs.value.length - 1;
    }
};
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
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("tab-container") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("tabs") }, });
    for (const [tab, index] of __VLS_getVForSourceType((__VLS_ctx.tabs))) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ onClick: (...[$event]) => {
                    __VLS_ctx.setActiveTab(index);
                    // @ts-ignore
                    [tabs, setActiveTab,];
                } }, key: ((index)), ...{ class: ((['tab', { 'active-tab': index === __VLS_ctx.activeTab }])) }, });
        __VLS_styleScopedClasses = (['tab', { 'active-tab': index === activeTab }]);
        (tab.name);
        __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (...[$event]) => {
                    __VLS_ctx.removeTab(index);
                    // @ts-ignore
                    [activeTab, removeTab,];
                } }, });
    }
    __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.addTab) }, ...{ class: ("add-tab") }, });
    // @ts-ignore
    [addTab,];
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("tab-content") }, });
    var __VLS_0 = {
        activeTab: ((__VLS_ctx.activeTab)), tabs: ((__VLS_ctx.tabs)),
    };
    // @ts-ignore
    [tabs, activeTab,];
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['tab-container'];
        __VLS_styleScopedClasses['tabs'];
        __VLS_styleScopedClasses['add-tab'];
        __VLS_styleScopedClasses['tab-content'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                tabs: tabs,
                activeTab: activeTab,
                setActiveTab: setActiveTab,
                addTab: addTab,
                removeTab: removeTab,
            };
        },
    });
}
const __VLS_component = (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
export default {};
;
