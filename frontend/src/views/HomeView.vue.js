const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
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
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 min-h-screen text-gray-300 pl-72 pt-24 relative") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("container mx-auto py-16 px-6") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h1, __VLS_intrinsicElements.h1)({ ...{ class: ("text-6xl font-extrabold mb-6 text-white leading-tight") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.p, __VLS_intrinsicElements.p)({ ...{ class: ("mb-8 text-2xl text-gray-400") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("grid grid-cols-1 md:grid-cols-3 gap-6") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({ ...{ class: ("text-3xl font-bold mb-2 text-primary") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.p, __VLS_intrinsicElements.p)({});
    __VLS_elementAsFunction(__VLS_intrinsicElements.code, __VLS_intrinsicElements.code)({ ...{ class: ("text-secondary") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({ ...{ class: ("text-3xl font-bold mb-2 text-primary") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.p, __VLS_intrinsicElements.p)({});
    __VLS_elementAsFunction(__VLS_intrinsicElements.code, __VLS_intrinsicElements.code)({ ...{ class: ("text-secondary") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("bg-white p-6 rounded-lg shadow-xl hover:shadow-2xl transition-shadow duration-300") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({ ...{ class: ("text-3xl font-bold mb-2 text-primary") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.p, __VLS_intrinsicElements.p)({});
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("absolute top-8 right-8") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.img, __VLS_intrinsicElements.img)({ src: ("/kubernetes-icon.svg"), alt: ("Kubernetes"), ...{ class: ("w-12 h-12 animate-spin-slow") }, });
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['bg-gradient-to-r'];
        __VLS_styleScopedClasses['from-gray-900'];
        __VLS_styleScopedClasses['via-gray-800'];
        __VLS_styleScopedClasses['to-gray-900'];
        __VLS_styleScopedClasses['min-h-screen'];
        __VLS_styleScopedClasses['text-gray-300'];
        __VLS_styleScopedClasses['pl-72'];
        __VLS_styleScopedClasses['pt-24'];
        __VLS_styleScopedClasses['relative'];
        __VLS_styleScopedClasses['container'];
        __VLS_styleScopedClasses['mx-auto'];
        __VLS_styleScopedClasses['py-16'];
        __VLS_styleScopedClasses['px-6'];
        __VLS_styleScopedClasses['text-6xl'];
        __VLS_styleScopedClasses['font-extrabold'];
        __VLS_styleScopedClasses['mb-6'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['leading-tight'];
        __VLS_styleScopedClasses['mb-8'];
        __VLS_styleScopedClasses['text-2xl'];
        __VLS_styleScopedClasses['text-gray-400'];
        __VLS_styleScopedClasses['grid'];
        __VLS_styleScopedClasses['grid-cols-1'];
        __VLS_styleScopedClasses['md:grid-cols-3'];
        __VLS_styleScopedClasses['gap-6'];
        __VLS_styleScopedClasses['bg-white'];
        __VLS_styleScopedClasses['p-6'];
        __VLS_styleScopedClasses['rounded-lg'];
        __VLS_styleScopedClasses['shadow-xl'];
        __VLS_styleScopedClasses['hover:shadow-2xl'];
        __VLS_styleScopedClasses['transition-shadow'];
        __VLS_styleScopedClasses['duration-300'];
        __VLS_styleScopedClasses['text-3xl'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['mb-2'];
        __VLS_styleScopedClasses['text-primary'];
        __VLS_styleScopedClasses['text-secondary'];
        __VLS_styleScopedClasses['bg-white'];
        __VLS_styleScopedClasses['p-6'];
        __VLS_styleScopedClasses['rounded-lg'];
        __VLS_styleScopedClasses['shadow-xl'];
        __VLS_styleScopedClasses['hover:shadow-2xl'];
        __VLS_styleScopedClasses['transition-shadow'];
        __VLS_styleScopedClasses['duration-300'];
        __VLS_styleScopedClasses['text-3xl'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['mb-2'];
        __VLS_styleScopedClasses['text-primary'];
        __VLS_styleScopedClasses['text-secondary'];
        __VLS_styleScopedClasses['bg-white'];
        __VLS_styleScopedClasses['p-6'];
        __VLS_styleScopedClasses['rounded-lg'];
        __VLS_styleScopedClasses['shadow-xl'];
        __VLS_styleScopedClasses['hover:shadow-2xl'];
        __VLS_styleScopedClasses['transition-shadow'];
        __VLS_styleScopedClasses['duration-300'];
        __VLS_styleScopedClasses['text-3xl'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['mb-2'];
        __VLS_styleScopedClasses['text-primary'];
        __VLS_styleScopedClasses['absolute'];
        __VLS_styleScopedClasses['top-8'];
        __VLS_styleScopedClasses['right-8'];
        __VLS_styleScopedClasses['w-12'];
        __VLS_styleScopedClasses['h-12'];
        __VLS_styleScopedClasses['animate-spin-slow'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {};
        },
    });
}
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
;
